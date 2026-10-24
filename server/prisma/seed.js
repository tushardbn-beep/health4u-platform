import 'dotenv/config';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
const prisma = new PrismaClient();
const services = [
 {slug:'consult',name:'Online Doctor Consultation',description:'Connect with a licensed clinician through a remote consultation.',indicativePrice:399},
 {slug:'homecare',name:'Home Healthcare',description:'Coordinated healthcare visits at home through verified partners.',indicativePrice:799},
 {slug:'labs',name:'Lab Tests',description:'Request diagnostic sample collection and partner laboratory testing.',indicativePrice:299},
 {slug:'nursing',name:'Nursing at Home',description:'Home nursing visits scheduled with verified nursing partners.',indicativePrice:999},
 {slug:'physio',name:'Physiotherapy',description:'Book a physiotherapy session with a verified partner professional.',indicativePrice:699},
 {slug:'medicine',name:'Medicine Delivery',description:'Request medicine delivery subject to prescription and pharmacy checks.',indicativePrice:99,requiresPrescription:true},
 {slug:'ambulance',name:'Ambulance Assistance',description:'Request local ambulance partner assistance; not an emergency dispatch guarantee.',indicativePrice:null}
];
try {
 for (const s of services) await prisma.service.upsert({where:{slug:s.slug},update:{name:s.name,description:s.description,indicativePrice:s.indicativePrice,requiresPrescription:s.requiresPrescription||false},create:s});
 if (process.env.BOOTSTRAP_ADMIN_EMAIL && process.env.BOOTSTRAP_ADMIN_PASSWORD && process.env.BOOTSTRAP_ADMIN_PHONE) {
  const email=process.env.BOOTSTRAP_ADMIN_EMAIL.toLowerCase();
  const existing=await prisma.user.findUnique({where:{email}});
  if(!existing){const passwordHash=await bcrypt.hash(process.env.BOOTSTRAP_ADMIN_PASSWORD,12);await prisma.user.create({data:{fullName:process.env.BOOTSTRAP_ADMIN_NAME||'HEALTH4U Administrator',email,phone:process.env.BOOTSTRAP_ADMIN_PHONE,passwordHash,role:'ADMIN'}});console.log('Bootstrap admin created.');}
  else console.log('Bootstrap admin email already exists; no password changes made.');
 } else console.log('Admin not bootstrapped. Set BOOTSTRAP_ADMIN_EMAIL, BOOTSTRAP_ADMIN_PASSWORD and BOOTSTRAP_ADMIN_PHONE in a secure environment, then rerun seed.');
 console.log('HEALTH4U services seeded.');
} finally { await prisma.$disconnect(); }
