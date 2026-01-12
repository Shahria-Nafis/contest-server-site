import { MongoClient, ObjectId } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

const uri = process.env.MONGODB_URI;
if (!uri) {
  console.warn('MONGODB_URI is not set. Set it in your .env file.');
}

let client;
let db;

export const toObjectId = (id) => {
  try {
    return new ObjectId(String(id));
  } catch {
    return null;
  }
};

export async function connectDb() {
  if (db) return db;
  client = new MongoClient(uri, { serverSelectionTimeoutMS: 5000 });
  await client.connect();
  db = client.db();
  await ensureIndexes();
  console.log('MongoDB Connected (driver)');
  return db;
}

export function getDb() {
  if (!db) throw new Error('DB not connected. Call connectDb() first.');
  return db;
}

export function collections() {
  const d = getDb();
  return {
    users: d.collection('users'),
    contests: d.collection('contests'),
    participations: d.collection('participations'),
    submissions: d.collection('submissions'),
  };
}

async function ensureIndexes() {
  const { users, participations } = collections();
  await users.createIndex({ uid: 1 }, { unique: true }).catch(() => {});
  await users.createIndex({ email: 1 }, { unique: true }).catch(() => {});
  await participations.createIndex({ user: 1, contest: 1 }, { unique: true }).catch(() => {});
}

export async function closeDb() {
  if (client) await client.close();
}
