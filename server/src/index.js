import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Razorpay from 'razorpay';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';

const app = express();
const prisma = new PrismaClient();
const port = Number(process.env.PORT || 4000);
const production = process.env.NODE_ENV === 'production';
const jwtSecret = process.env.JWT_SECRET;
if (production && (!jwtSecret || jwtSecret.length < 32)) throw new Error('JWT_SECRET must be at least 32 characters in production.');
app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: (process.env.CLIENT_ORIGIN || 'http://localhost:5173').split(',').map(s => s.trim()), credentials: true }));
app.use('/api/', rateLimit({ windowMs: 15 * 60 * 1000, limit: 180, standardHeaders: 'draft-7', legacyHeaders: false }));
app.use(express.json({ limit: '32kb', verify:(req,_res,buf)=>{ if(req.originalUrl.startsWith('/api/payments/razorpay/webhook')) req.rawBody=Buffer.from(buf); } }));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
const bookingLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: 'draft-7', legacyHeaders: false, message:{error:'Too many booking requests. Please wait before trying again.'} });
const paymentLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false });
const slugToId = new Map();
const bookingSchema = z.object({
  name: z.string().trim().min(2).max(100),
  phone: z.string().trim().regex(/^[0-9+() -]{8,18}$/),
  email: z.string().trim().email().max(180).optional().or(z.literal('')),
  city: z.string().trim().min(2).max(100),
  address: z.string().trim().min(4).max(250),
  date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  time: z.string().trim().min(2).max(80),
  paymentMethod: z.enum(['Online payment', 'Cash on service']).default('Online payment'),
  serviceId: z.string().min(2).max(100),
  serviceName: z.string().trim().min(2).max(120).optional(),
  notes: z.string().max(300).optional().default('')
});
const loginSchema = z.object({ email: z.string().email().max(180), password: z.string().min(8).max(200) });
const bookingStatusSchema = z.object({ status: z.enum(['UNDER_REVIEW','CONFIRMED','PROVIDER_ASSIGNED','IN_PROGRESS','COMPLETED','CANCELLED','REJECTED']), providerId: z.string().optional(), finalPrice: z.number().int().nonnegative().max(10000000).optional() });
const availabilitySchema = z.object({ startsAt: z.string().datetime(), endsAt: z.string().datetime(), isAvailable: z.boolean().default(true) }).refine(v => new Date(v.endsAt) > new Date(v.startsAt), { message: 'End time must be after start time.' });

function auth(roles = []) {
  return (req, res, next) => {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Authentication required.' });
    try {
      const payload = jwt.verify(token, jwtSecret || 'local-development-secret-change-before-deploy');
      if (roles.length && !roles.includes(payload.role)) return res.status(403).json({ error: 'You do not have permission for this action.' });
      req.user = payload;
      next();
    } catch { return res.status(401).json({ error: 'Session is invalid or expired.' }); }
  };
}
const publicBooking = b => ({ id:b.id, reference:b.reference, name:b.patient.fullName, phone:b.patient.phone, city:b.city, address:b.address, date:b.requestedAt.toISOString().slice(0,10), time:b.timeWindow, paymentMethod:b.paymentMethod, serviceId:b.service.slug, serviceName:b.service.name, price:b.finalPrice ?? b.indicativePrice ?? 0, status:b.status, createdAt:b.createdAt.toISOString(), provider:b.provider?.displayName || null, demo:false });

app.get('/api/health', async (_req, res) => {
  let database = 'disconnected'; try { await prisma.$queryRaw`SELECT 1`; database = 'connected'; } catch {}
  res.json({ status: 'ok', app: 'HEALTH4U API', mode: production ? 'production' : 'development', database, payments: Boolean(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET) ? 'configured' : 'not-configured' });
});
app.get('/api/services', async (_req, res, next) => { try { res.json(await prisma.service.findMany({ where:{isActive:true}, orderBy:{name:'asc'}, select:{id:true,slug:true,name:true,description:true,indicativePrice:true,currency:true,requiresPrescription:true} })); } catch(e) { next(e); } });

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const parsed = loginSchema.safeParse(req.body); if (!parsed.success) return res.status(400).json({ error:'Enter a valid email and password.' });
    const user = await prisma.user.findUnique({ where:{email:parsed.data.email.toLowerCase()}, include:{provider:true} });
    if (!user || !user.isActive || !user.passwordHash || !(await bcrypt.compare(parsed.data.password, user.passwordHash))) return res.status(401).json({ error:'Invalid credentials.' });
    if (!['ADMIN','PROVIDER','SUPPORT'].includes(user.role)) return res.status(403).json({ error:'Staff access only.' });
    if (user.role === 'PROVIDER' && user.provider?.verificationStatus !== 'VERIFIED') return res.status(403).json({ error:'Provider verification is required before access is enabled.' });
    const token = jwt.sign({ sub:user.id, role:user.role, providerId:user.provider?.id || null }, jwtSecret || 'local-development-secret-change-before-deploy', { expiresIn:'8h', issuer:'health4u', audience:'health4u-web' });
    await prisma.auditEvent.create({ data:{ actorId:user.id, action:'STAFF_LOGIN', entityType:'User', entityId:user.id } });
    res.json({ token, expiresIn:28800, user:{ id:user.id, name:user.fullName, email:user.email, role:user.role, providerId:user.provider?.id || null } });
  } catch(e) { next(e); }
});

app.get('/api/availability', async (req, res, next) => {
  try {
    const q = z.object({ service:StringSchema(), city:z.string().min(2).max(100), date:z.string().regex(/^\d{4}-\d{2}-\d{2}$/) }).safeParse(req.query);
    if (!q.success) return res.status(400).json({ error:'service, city and date are required.' });
    const service = await prisma.service.findFirst({ where:{ OR:[{id:q.data.service},{slug:q.data.service}], isActive:true } });
    if (!service) return res.status(404).json({ error:'Service not found.' });
    const start = new Date(`${q.data.date}T00:00:00+05:30`), end = new Date(start.getTime()+86400000); // Jaipur local calendar day
    const providers = await prisma.providerProfile.findMany({ where:{ verificationStatus:'VERIFIED', isAvailable:true, serviceCities:{ has:q.data.city }, services:{ some:{ serviceId:service.id } }, availability:{ some:{ isAvailable:true, startsAt:{lt:end}, endsAt:{gt:start} } } }, include:{availability:{where:{isAvailable:true,startsAt:{lt:end},endsAt:{gt:start}},orderBy:{startsAt:'asc'}}} });
    const slots = [];
    for (const p of providers) for (const a of p.availability) {
      const from = Math.max(a.startsAt.getTime(), start.getTime()), to = Math.min(a.endsAt.getTime(), end.getTime());
      for (let t = Math.ceil(from/3600000)*3600000; t+3600000<=to; t+=3600000) {
        const slotEnd = new Date(t+3600000);
        const conflict = await prisma.booking.findFirst({ where:{ providerId:p.id, status:{notIn:['CANCELLED','REJECTED']}, requestedAt:{lt:slotEnd,gte:new Date(t-3600000)} } });
        if (!conflict) slots.push({ startsAt:new Date(t).toISOString(), providerId:p.id });
      }
    }
    res.json({ service:service.slug, city:q.data.city, date:q.data.date, slots:slots.sort((a,b)=>a.startsAt.localeCompare(b.startsAt)), message:slots.length?'Availability based on verified partner schedules.':'No partner slots currently listed for this date.' });
  } catch(e) { next(e); }
});
function StringSchema(){ return z.string().min(1).max(100); }

app.post('/api/bookings', bookingLimiter, async (req, res, next) => {
  try {
    const parsed = bookingSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error:'Please check the required booking fields.', details:parsed.error.flatten().fieldErrors });
    const d = parsed.data; const requestedAt = new Date(`${d.date}T00:00:00+05:30`); // Jaipur local date
    if (Number.isNaN(requestedAt.getTime()) || requestedAt < new Date(new Date().toISOString().slice(0,10)+'T00:00:00.000Z')) return res.status(400).json({ error:'Choose today or a future date.' });
    const service = await prisma.service.findFirst({ where:{ OR:[{id:d.serviceId},{slug:d.serviceId}], isActive:true } });
    if (!service) return res.status(400).json({ error:'This service is not currently available for booking.' });
    const match = d.time.match(/^\s*(\d{1,2})(?::(\d{2}))?\s*(AM|PM)\s*$/i);
    let slotStart = null;
    if (match) { let h=Number(match[1])%12; if(match[3].toUpperCase()==='PM')h+=12; slotStart=new Date(`${d.date}T${String(h).padStart(2,'0')}:${match[2]||'00'}:00+05:30`); }
    let patient = await prisma.user.findUnique({where:{phone:d.phone}});
    if(patient && patient.role!=='PATIENT') return res.status(409).json({error:'This contact is already registered for a staff account. Please contact support.'});
    if(patient && patient.fullName.trim().toLowerCase()!==d.name.trim().toLowerCase()) return res.status(409).json({error:'A patient profile already exists for this phone number. Verify the phone with support before changing profile details.'});
    if(!patient && d.email){const emailOwner=await prisma.user.findUnique({where:{email:d.email.toLowerCase()}});if(emailOwner)return res.status(409).json({error:'This email is already linked to another profile. Contact support to verify your details.'});}
    if(!patient) patient=await prisma.user.create({data:{fullName:d.name,phone:d.phone,...(d.email?{email:d.email.toLowerCase()}:{}),role:'PATIENT'}});
    const reference = `H4U-${new Date().getFullYear()}-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
    let providerId = null; let status = 'REQUESTED';
    if (slotStart) {
      const slotEnd = new Date(slotStart.getTime()+3600000);
      const candidates = await prisma.providerProfile.findMany({ where:{verificationStatus:'VERIFIED',isAvailable:true,serviceCities:{has:d.city},services:{some:{serviceId:service.id}},availability:{some:{isAvailable:true,startsAt:{lte:slotStart},endsAt:{gte:slotEnd}}}} });
      for (const p of candidates) {
        const conflict = await prisma.booking.findFirst({where:{providerId:p.id,status:{notIn:['CANCELLED','REJECTED']},requestedAt:{lt:slotEnd,gte:new Date(slotStart.getTime()-3600000)}}});
        if(!conflict){providerId=p.id;status='PROVIDER_ASSIGNED';break;}
      }
    }
    const booking = await prisma.booking.create({ data:{ reference,patientId:patient.id,serviceId:service.id,providerId,status,city:d.city,address:d.address,requestedAt:slotStart||requestedAt,timeWindow:d.time,notes:d.notes||null,indicativePrice:service.indicativePrice,paymentMethod:d.paymentMethod }, include:{patient:true,service:true,provider:true} });
    await prisma.payment.create({data:{bookingId:booking.id,amount:service.indicativePrice||0,currency:'INR',status:d.paymentMethod==='Cash on service'?'CASH_DUE':'PENDING',providerName:process.env.RAZORPAY_KEY_ID?'razorpay':null}});
    await prisma.auditEvent.create({data:{action:'BOOKING_CREATED',entityType:'Booking',entityId:booking.id,metadata:{service:service.slug,city:d.city,paymentMethod:d.paymentMethod}}});
    res.status(201).json({...publicBooking(booking), availabilityStatus:providerId?'partner-slot-matched':'manual-confirmation-required', message:providerId?'A partner slot matched. The operations team must still confirm the booking.':'Request received; partner availability needs manual confirmation.'});
  } catch(e) { next(e); }
});

app.get('/api/bookings', auth(['ADMIN','SUPPORT']), async (req,res,next) => {
  try { const rows=await prisma.booking.findMany({include:{patient:true,service:true,provider:true,payment:true},orderBy:{createdAt:'desc'},take:250}); res.json(rows.map(publicBooking)); } catch(e){next(e);} });
app.get('/api/provider/bookings', auth(['PROVIDER']), async (req,res,next) => {
  try { const p=await prisma.providerProfile.findUnique({where:{userId:req.user.sub}}); if(!p)return res.status(403).json({error:'Provider profile missing.'}); const rows=await prisma.booking.findMany({where:{providerId:p.id},include:{patient:true,service:true,provider:true},orderBy:{requestedAt:'asc'},take:100}); res.json(rows.map(publicBooking)); } catch(e){next(e);} });
app.patch('/api/bookings/:id/status', auth(['ADMIN','SUPPORT','PROVIDER']), async (req,res,next) => {
  try {
    const parsed=bookingStatusSchema.safeParse(req.body); if(!parsed.success)return res.status(400).json({error:'Invalid status update.'});
    const existing=await prisma.booking.findUnique({where:{id:req.params.id},include:{provider:true}}); if(!existing)return res.status(404).json({error:'Booking not found.'});
    if(req.user.role==='PROVIDER'){const p=await prisma.providerProfile.findUnique({where:{userId:req.user.sub}});if(!p||existing.providerId!==p.id)return res.status(403).json({error:'Providers can update only their assigned bookings.'});if(parsed.data.providerId||parsed.data.finalPrice!==undefined||!['IN_PROGRESS','COMPLETED'].includes(parsed.data.status))return res.status(403).json({error:'Providers may only mark their assigned booking in progress or completed.'});}
    let providerId=parsed.data.providerId||existing.providerId;
    if(providerId){const provider=await prisma.providerProfile.findUnique({where:{id:providerId}});if(!provider||provider.verificationStatus!=='VERIFIED')return res.status(400).json({error:'Only verified providers can be assigned.'});}
    const resolvedPrice=parsed.data.finalPrice!==undefined?parsed.data.finalPrice:((['CONFIRMED','PROVIDER_ASSIGNED'].includes(parsed.data.status)&&existing.finalPrice===null)?existing.indicativePrice:undefined);const updated=await prisma.$transaction(async tx=>{const row=await tx.booking.update({where:{id:existing.id},data:{status:parsed.data.status,providerId, ...(resolvedPrice!==undefined?{finalPrice:resolvedPrice}: {})},include:{patient:true,service:true,provider:true}});if(resolvedPrice!==undefined&&resolvedPrice!==null)await tx.payment.updateMany({where:{bookingId:existing.id,status:{in:['PENDING','FAILED','CASH_DUE']}},data:{amount:resolvedPrice}});return row;});
    await prisma.auditEvent.create({data:{actorId:req.user.sub,action:'BOOKING_UPDATED',entityType:'Booking',entityId:updated.id,metadata:{status:updated.status,providerId:updated.providerId}}});
    res.json(publicBooking(updated));
  }catch(e){next(e);}
});
app.post('/api/provider/availability', auth(['PROVIDER']), async(req,res,next)=>{
  try{const parsed=availabilitySchema.safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Provide valid start and end times.'});const p=await prisma.providerProfile.findUnique({where:{userId:req.user.sub}});if(!p||p.verificationStatus!=='VERIFIED')return res.status(403).json({error:'Verified provider profile required.'});const row=await prisma.$transaction(async tx=>{const availability=await tx.providerAvailability.create({data:{providerId:p.id,...parsed.data,startsAt:new Date(parsed.data.startsAt),endsAt:new Date(parsed.data.endsAt)}});if(parsed.data.isAvailable)await tx.providerProfile.update({where:{id:p.id},data:{isAvailable:true}});return availability;});await prisma.auditEvent.create({data:{actorId:req.user.sub,action:'PROVIDER_AVAILABILITY_CREATED',entityType:'ProviderAvailability',entityId:row.id}});res.status(201).json(row);}catch(e){next(e);}
});
app.get('/api/admin/providers', auth(['ADMIN','SUPPORT']), async(_req,res,next)=>{try{res.json(await prisma.providerProfile.findMany({include:{user:{select:{id:true,fullName:true,email:true,phone:true,isActive:true}},services:{include:{service:{select:{id:true,name:true,slug:true}}}},availability:{where:{endsAt:{gte:new Date()}},orderBy:{startsAt:'asc'},take:20}},orderBy:{createdAt:'desc'}}));}catch(e){next(e);}});
app.post('/api/admin/providers', auth(['ADMIN']), async(req,res,next)=>{
 try{const parsed=z.object({fullName:z.string().trim().min(2).max(100),email:z.string().email().max(180),phone:z.string().regex(/^[0-9+() -]{8,18}$/),password:z.string().min(12).max(200),displayName:z.string().trim().min(2).max(100),credentialsSummary:z.string().trim().min(3).max(500),serviceCities:z.array(z.string().trim().min(2).max(100)).min(1).max(30),serviceIds:z.array(z.string().min(2).max(100)).min(1).max(20)}).safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Check provider fields; initial password must be at least 12 characters.'});const d=parsed.data;const services=await prisma.service.findMany({where:{id:{in:d.serviceIds},isActive:true},select:{id:true}});if(services.length!==new Set(d.serviceIds).size)return res.status(400).json({error:'One or more service IDs are invalid or inactive.'});const exists=await prisma.user.findFirst({where:{OR:[{email:d.email.toLowerCase()},{phone:d.phone}]}});if(exists)return res.status(409).json({error:'A user with this email or phone already exists.'});const passwordHash=await bcrypt.hash(d.password,12);const provider=await prisma.$transaction(async tx=>{const user=await tx.user.create({data:{fullName:d.fullName,email:d.email.toLowerCase(),phone:d.phone,passwordHash,role:'PROVIDER'}});const profile=await tx.providerProfile.create({data:{userId:user.id,displayName:d.displayName,credentialsSummary:d.credentialsSummary,serviceCities:d.serviceCities,verificationStatus:'PENDING',isAvailable:false,services:{create:services.map(s=>({serviceId:s.id}))}}});await tx.auditEvent.create({data:{actorId:req.user.sub,action:'PROVIDER_CREATED',entityType:'ProviderProfile',entityId:profile.id,metadata:{serviceCount:services.length,verificationStatus:'PENDING'}}});return {id:profile.id,userId:user.id,displayName:profile.displayName,verificationStatus:profile.verificationStatus,serviceCities:profile.serviceCities};});res.status(201).json(provider);}catch(e){next(e);}
});
app.patch('/api/admin/providers/:id/verification', auth(['ADMIN']), async(req,res,next)=>{try{const parsed=z.object({verificationStatus:z.enum(['PENDING','VERIFIED','REJECTED']),isAvailable:z.boolean().optional()}).safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Invalid provider verification update.'});const row=await prisma.providerProfile.update({where:{id:req.params.id},data:parsed.data});await prisma.auditEvent.create({data:{actorId:req.user.sub,action:'PROVIDER_VERIFICATION_UPDATED',entityType:'ProviderProfile',entityId:row.id,metadata:parsed.data}});res.json(row);}catch(e){next(e);}});

app.post('/api/payments/order', paymentLimiter, async(req,res,next)=>{
  try{
    if(!process.env.RAZORPAY_KEY_ID||!process.env.RAZORPAY_KEY_SECRET)return res.status(503).json({error:'Online payments are not configured. Choose cash on service or contact support.'});
    const parsed=z.object({bookingReference:z.string().min(5).max(40),phone:z.string().trim().regex(/^[0-9+() -]{8,18}$/)}).safeParse(req.body);if(!parsed.success)return res.status(400).json({error:'Booking reference and booking phone number are required.'});
    const booking=await prisma.booking.findUnique({where:{reference:parsed.data.bookingReference},include:{patient:true,service:true,payment:true}});if(!booking||booking.patient.phone.replace(/\D/g,'')!==parsed.data.phone.replace(/\D/g,''))return res.status(404).json({error:'Booking not found for these details.'});if(!['CONFIRMED','PROVIDER_ASSIGNED'].includes(booking.status)||booking.finalPrice===null)return res.status(409).json({error:'Operations must confirm the booking and final price before checkout.'});if(!booking.payment||booking.payment.amount<=0)return res.status(400).json({error:'A confirmed payable amount is required before checkout.'});if(booking.payment.status==='PAID')return res.status(409).json({error:'This booking is already paid.'});
    const razorpay=new Razorpay({key_id:process.env.RAZORPAY_KEY_ID,key_secret:process.env.RAZORPAY_KEY_SECRET});const order=await razorpay.orders.create({amount:booking.payment.amount*100,currency:'INR',receipt:booking.reference,notes:{bookingId:booking.id,bookingReference:booking.reference}});await prisma.payment.update({where:{bookingId:booking.id},data:{providerName:'razorpay',providerOrderId:order.id}});res.json({orderId:order.id,amount:order.amount,currency:order.currency,keyId:process.env.RAZORPAY_KEY_ID,bookingReference:booking.reference});
  }catch(e){next(e);}
});
app.post('/api/payments/razorpay/webhook', async(req,res,next)=>{
  try{const secret=process.env.RAZORPAY_WEBHOOK_SECRET;if(!secret)return res.status(503).json({error:'Payment webhook is not configured.'});const signature=req.headers['x-razorpay-signature'];const expected=crypto.createHmac('sha256',secret).update(req.rawBody || Buffer.from('')).digest('hex');if(typeof signature!=='string'||signature.length!==expected.length||!crypto.timingSafeEqual(Buffer.from(signature),Buffer.from(expected)))return res.status(400).json({error:'Invalid webhook signature.'});const event=JSON.parse((req.rawBody || Buffer.from('{}')).toString('utf8'));if(event.event==='payment.captured'){const payment=event.payload?.payment?.entity;const bookingId=payment?.notes?.bookingId;if(bookingId){const record=await prisma.payment.findUnique({where:{bookingId}});if(record&&record.providerOrderId===payment.order_id){await prisma.payment.update({where:{bookingId},data:{providerPaymentId:payment.id,status:'PAID',paidAt:new Date()}});}}}else if(event.event==='payment.failed'){const payment=event.payload?.payment?.entity;const bookingId=payment?.notes?.bookingId;if(bookingId)await prisma.payment.updateMany({where:{bookingId,status:{not:'PAID'}},data:{status:'FAILED'}});}res.json({received:true});}catch(e){next(e);}
});

// In production, serve the built React app from the same public origin as the API.
// This lets the deployed site work from any device without localhost API URLs.
app.use('/api', (_req,res)=>res.status(404).json({error:'API route not found.'}));
if (production) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const clientDist = path.resolve(here, '../../client/dist');
  app.use(express.static(clientDist));
  app.get('*', (_req,res,next)=>res.sendFile(path.join(clientDist, 'index.html'), err=>{ if(err) next(err); }));
}
app.use((_req,res)=>res.status(404).json({error:'Route not found.'}));
app.use((err,_req,res,_next)=>{console.error('API error:',err?.message||err);res.status(500).json({error:production?'Unexpected server error.':'Unexpected server error.', ...(production?{}:{detail:err?.message})});});
const server=app.listen(port,()=>console.log(`HEALTH4U API listening on port ${port}`));
async function shutdown(){server.close();await prisma.$disconnect();process.exit(0);}process.on('SIGTERM',shutdown);process.on('SIGINT',shutdown);
