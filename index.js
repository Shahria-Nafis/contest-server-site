import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { collections, connectDb, toObjectId } from './db.js';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import Stripe from 'stripe';

dotenv.config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(helmet());
app.use(morgan('dev'));

if (process.env.NODE_ENV === 'production') {
  const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
  app.use('/api', apiLimiter);
} else {
  const apiLimiter = rateLimit({ windowMs: 5 * 60 * 1000, max: 1000, standardHeaders: true, legacyHeaders: false });
  app.use('/api', apiLimiter);
}

const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

await connectDb();
const { users: User, contests: Contest, participations: Participation, submissions: Submission } = collections();

const { JWT_SECRET } = process.env;
if (!JWT_SECRET) {
  console.warn('JWT_SECRET is not set. Set it in your .env file.');
}

const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization || '';
  const [scheme, token] = auth.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ message: 'Unauthorized: Bearer token required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Unauthorized: Invalid or expired token' });
  }
};

const requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ message: 'Forbidden: insufficient role' });
  }
  next();
};

const getDbUserByUid = async (uid) => {
  if (!uid) return null;
  return await User.findOne({ uid });
};

app.get('/', (req, res) => {
  res.json({ message: 'ContestHub Server is running' });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { uid, email, displayName, photoURL } = req.body;

    if (!email) {
      return res.status(400).json({ message: 'Email is required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const userUid = uid || `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

    const newUser = {
      uid: userUid,
      email,
      displayName: displayName || 'Anonymous User',
      photoURL: photoURL || null,
      role: 'user',
      createdAt: new Date(),
      updatedAt: new Date()
    };
    await User.insertOne(newUser);
    
    res.status(201).json({ message: 'User registered successfully', user: newUser });
  } catch (error) {
    res.status(500).json({ message: 'Registration error', error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { uid, email } = req.body;
    if (!uid && !email) {
      return res.status(400).json({ message: 'uid or email is required' });
    }

    const user = await User.findOne(uid ? { uid } : { email });
    if (!user) {
      return res.status(404).json({ message: 'User not found. Please register first.' });
    }

    const token = jwt.sign(
      { uid: user.uid, role: user.role, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, user });
  } catch (error) {
    res.status(500).json({ message: 'Login error', error: error.message });
  }
});

app.get('/api/users/:uid/role', async (req, res) => {
  try {
    const user = await User.findOne({ uid: req.params.uid });
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ role: user.role || 'user' });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching role', error: error.message });
  }
});

app.get('/api/users/:userId', async (req, res) => {
  try {
    const oid = toObjectId(req.params.userId);
    const user = oid ? await User.findOne({ _id: oid }) : null;
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user', error: error.message });
  }
});

app.put('/api/users/profile/:uid', async (req, res) => {
  try {
    const { displayName, photoURL, phone, address, bio } = req.body;

    const result = await User.findOneAndUpdate(
      { uid: req.params.uid },
      { $set: { displayName, photoURL, phone, address, bio, updatedAt: new Date() } },
      { returnDocument: 'after' }
    );
    const user = result.value;

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    res.status(500).json({ message: 'Update error', error: error.message });
  }
});

app.get('/api/contests', async (req, res) => {
  try {
    const {
      status = 'approved',
      type,
      q,
      sort = 'recent',
      page = 1,
      limit = 10
    } = req.query;

    const query = {};
    if (status) query.status = status;
    if (type) query.contestType = type;
    if (q) query.name = { $regex: q, $options: 'i' };

    const skip = (Number(page) - 1) * Number(limit);
    const sortMap = {
      popular: { participantsCount: -1 },
      deadline: { deadline: 1 },
      recent: { createdAt: -1 }
    };

    const pipeline = [
      { $match: query },
      { $sort: sortMap[sort] || sortMap.recent },
      { $skip: skip },
      { $limit: Number(limit) },
      {
        $lookup: {
          from: 'users',
          localField: 'creator',
          foreignField: '_id',
          as: 'creator'
        }
      },
      { $unwind: { path: '$creator', preserveNullAndEmptyArrays: true } },
      { $project: { 'creator.displayName': 1, 'creator.email': 1, name: 1, image: 1, contestType: 1, participantsCount: 1, prizeMoney: 1, status: 1, deadline: 1, createdAt: 1 } }
    ];
    const items = await Contest.aggregate(pipeline).toArray();
    const total = await Contest.countDocuments(query);

    res.json({
      data: items,
      pagination: { page: Number(page), limit: Number(limit), total, pages: Math.ceil(total / Number(limit)) }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching contests', error: error.message });
  }
});

app.get('/api/contests/popular', async (req, res) => {
  try {
    const contests = await Contest.aggregate([
      { $match: { status: 'approved' } },
      { $sort: { participantsCount: -1 } },
      { $limit: 5 },
      { $lookup: { from: 'users', localField: 'creator', foreignField: '_id', as: 'creator' } },
      { $unwind: { path: '$creator', preserveNullAndEmptyArrays: true } },
      { $project: { 'creator.displayName': 1, 'creator.email': 1, name: 1, image: 1, contestType: 1, participantsCount: 1, prizeMoney: 1 } }
    ]).toArray();
    res.json(contests);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching popular contests', error: error.message });
  }
});

app.get('/api/contests/:id', async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    const contestArr = await Contest.aggregate([
      { $match: { _id: oid } },
      { $lookup: { from: 'users', localField: 'creator', foreignField: '_id', as: 'creator' } },
      { $unwind: { path: '$creator', preserveNullAndEmptyArrays: true } }
    ]).toArray();
    const contest = contestArr[0];
    
    if (!contest) {
      return res.status(404).json({ message: 'Contest not found' });
    }

    res.json(contest);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching contest', error: error.message });
  }
});

app.post('/api/contests', verifyToken, async (req, res) => {
  try {
    const { name, description, image, contestType, taskInstruction, price, prizeMoney, deadline } = req.body;

    const creator = await User.findOne({ uid: req.user.uid });
    
    if (creator.role !== 'creator' && creator.role !== 'admin') {
      return res.status(403).json({ message: 'Only creators can create contests' });
    }

    const newContest = {
      name,
      description,
      image,
      contestType,
      taskInstruction,
      creator: creator._id,
      price,
      prizeMoney,
      deadline: new Date(deadline),
      status: 'pending'
    };
    const inserted = await Contest.insertOne(newContest);
    res.status(201).json({ message: 'Contest created successfully', contest: { ...newContest, _id: inserted.insertedId } });
  } catch (error) {
    res.status(500).json({ message: 'Error creating contest', error: error.message });
  }
});

app.put('/api/contests/:id', verifyToken, async (req, res) => {
  try {
    const { name, description, image, contestType, taskInstruction, price, prizeMoney, deadline } = req.body;
    const dbUser = await getDbUserByUid(req.user.uid);
    const oid = toObjectId(req.params.id);
    const contestDoc = await Contest.findOne({ _id: oid });
    if (!contestDoc) {
      return res.status(404).json({ message: 'Contest not found' });
    }
    if (String(contestDoc.creator) !== String(dbUser._id)) {
      return res.status(403).json({ message: 'Only contest owner can update' });
    }
    if (contestDoc.status !== 'pending') {
      return res.status(400).json({ message: 'Only pending contests can be updated' });
    }

    const updated = await Contest.findOneAndUpdate(
      { _id: oid },
      { $set: { name, description, image, contestType, taskInstruction, price, prizeMoney, deadline: new Date(deadline) } },
      { returnDocument: 'after' }
    );
    const contest = updated.value;

    if (!contest) {
      return res.status(404).json({ message: 'Contest not found' });
    }

    res.json({ message: 'Contest updated successfully', contest });
  } catch (error) {
    res.status(500).json({ message: 'Error updating contest', error: error.message });
  }
});

app.delete('/api/contests/:id', verifyToken, async (req, res) => {
  try {
    const dbUser = await getDbUserByUid(req.user.uid);
    const oid = toObjectId(req.params.id);
    const contestDoc = await Contest.findOne({ _id: oid });
    if (!contestDoc) {
      return res.status(404).json({ message: 'Contest not found' });
    }
    if (String(contestDoc.creator) !== String(dbUser._id)) {
      return res.status(403).json({ message: 'Only contest owner can delete' });
    }
    if (contestDoc.status !== 'pending') {
      return res.status(400).json({ message: 'Only pending contests can be deleted' });
    }
    await Contest.deleteOne({ _id: oid });
    res.json({ message: 'Contest deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting contest', error: error.message });
  }
});

app.put('/api/admin/users/:userId/role', verifyToken, async (req, res) => {
  try {
    const { role } = req.body;

    const adminUser = await User.findOne({ uid: req.user.uid });
    if (adminUser.role !== 'admin') {
      return res.status(403).json({ message: 'Only admins can change roles' });
    }

    const oid = toObjectId(req.params.userId);
    const result = await User.findOneAndUpdate(
      { _id: oid },
      { $set: { role } },
      { returnDocument: 'after' }
    );
    const user = result.value;

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({ message: 'Role updated successfully', user });
  } catch (error) {
    res.status(500).json({ message: 'Error updating role', error: error.message });
  }
});

app.get('/api/admin/users', verifyToken, async (req, res) => {
  try {
    const adminUser = await User.findOne({ uid: req.user.uid });
    if (adminUser.role !== 'admin') {
      return res.status(403).json({ message: 'Only admins can view users' });
    }

    const users = await User.find({}).project({ password: 0 }).toArray();
    res.json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users', error: error.message });
  }
});

app.put('/api/admin/contests/:id/approve', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    const result = await Contest.findOneAndUpdate({ _id: oid }, { $set: { status: 'approved' } }, { returnDocument: 'after' });
    const contest = result.value;
    if (!contest) return res.status(404).json({ message: 'Contest not found' });
    res.json({ message: 'Contest approved', contest });
  } catch (error) {
    res.status(500).json({ message: 'Error approving contest', error: error.message });
  }
});

app.put('/api/admin/contests/:id/reject', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    const result = await Contest.findOneAndUpdate({ _id: oid }, { $set: { status: 'rejected' } }, { returnDocument: 'after' });
    const contest = result.value;
    if (!contest) return res.status(404).json({ message: 'Contest not found' });
    res.json({ message: 'Contest rejected', contest });
  } catch (error) {
    res.status(500).json({ message: 'Error rejecting contest', error: error.message });
  }
});

app.delete('/api/admin/contests/:id', verifyToken, requireRole('admin'), async (req, res) => {
  try {
    const oid = toObjectId(req.params.id);
    const result = await Contest.findOneAndDelete({ _id: oid });
    const contest = result.value;
    if (!contest) return res.status(404).json({ message: 'Contest not found' });
    res.json({ message: 'Contest deleted' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting contest', error: error.message });
  }
});

app.post('/api/payments/create-intent', verifyToken, async (req, res) => {
  try {
    const { contestId } = req.body;
    if (!contestId) {
      return res.status(400).json({ message: 'contestId is required' });
    }

    const contest = await Contest.findOne({ _id: toObjectId(contestId) });
    if (!contest) {
      return res.status(404).json({ message: 'Contest not found' });
    }
    if (new Date(contest.deadline) < new Date()) {
      return res.status(400).json({ message: 'Contest Ended' });
    }

    const amount = Math.max(Math.round(Number(contest.price || 0) * 100), 0);

    if (!stripe || !Number.isFinite(amount) || amount < 50) {
      return res.json({ clientSecret: 'mock_client_secret_demo_mode' });
    }

    const paymentIntent = await stripe.paymentIntents.create({
      amount,
      currency: 'usd',
      metadata: {
        contestId: contest._id.toString(),
        userUid: req.user.uid,
      },
    });

    res.json({ clientSecret: paymentIntent.client_secret });
  } catch (error) {
    console.error('Payment intent error:', error.message);
    res.status(500).json({ message: 'Error creating payment intent', error: error.message });
  }
});

app.post('/api/contests/:id/register', verifyToken, async (req, res) => {
  try {
    const contest = await Contest.findOne({ _id: toObjectId(req.params.id) });
    if (!contest) return res.status(404).json({ message: 'Contest not found' });
    if (new Date(contest.deadline) < new Date()) {
      return res.status(400).json({ message: 'Contest Ended' });
    }
    const dbUser = await getDbUserByUid(req.user.uid);
    if (!dbUser) return res.status(404).json({ message: 'User not found' });

    const partResult = await Participation.findOneAndUpdate(
      { user: dbUser._id, contest: contest._id },
      { $set: { amount: contest.price, paymentStatus: 'paid', createdAt: new Date() } },
      { upsert: true, returnDocument: 'after' }
    );
    const participation = partResult.value;

    const count = await Participation.countDocuments({ contest: contest._id, paymentStatus: 'paid' });
    if (contest.participantsCount !== count) {
      contest.participantsCount = count;
      await Contest.updateOne({ _id: contest._id }, { $set: { participantsCount: count } });
    }

    res.json({ message: 'Registered successfully', participation });
  } catch (error) {
    res.status(500).json({ message: 'Error registering', error: error.message });
  }
});

app.post('/api/contests/:id/submissions', verifyToken, async (req, res) => {
  try {
    const { content } = req.body;
    if (!content) return res.status(400).json({ message: 'Content is required' });
    const contest = await Contest.findOne({ _id: toObjectId(req.params.id) });
    if (!contest) return res.status(404).json({ message: 'Contest not found' });
    const dbUser = await getDbUserByUid(req.user.uid);

    const hasPaid = await Participation.findOne({ user: dbUser._id, contest: contest._id, paymentStatus: 'paid' });
    if (!hasPaid) return res.status(403).json({ message: 'You must register first' });

    const subResult = await Submission.findOneAndUpdate(
      { contest: contest._id, user: dbUser._id },
      { $set: { content, createdAt: new Date() } },
      { upsert: true, returnDocument: 'after' }
    );
    const submission = subResult.value;

    res.status(201).json({ message: 'Submission saved', submission });
  } catch (error) {
    res.status(500).json({ message: 'Error submitting task', error: error.message });
  }
});

app.get('/api/contests/:id/submissions', verifyToken, async (req, res) => {
  try {
    const contest = await Contest.findOne({ _id: toObjectId(req.params.id) });
    if (!contest) return res.status(404).json({ message: 'Contest not found' });
    const dbUser = await getDbUserByUid(req.user.uid);
    if (String(contest.creator) !== String(dbUser._id) && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Only creator/admin can view submissions' });
    }

    const submissions = await Submission.aggregate([
      { $match: { contest: contest._id } },
      { $lookup: { from: 'users', localField: 'user', foreignField: '_id', as: 'user' } },
      { $unwind: { path: '$user', preserveNullAndEmptyArrays: true } },
      { $project: { content: 1, createdAt: 1, 'user.displayName': 1, 'user.email': 1, 'user.photoURL': 1 } }
    ]).toArray();
    res.json(submissions);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching submissions', error: error.message });
  }
});

app.post('/api/contests/:id/declare-winner', verifyToken, async (req, res) => {
  try {
    const { submissionId } = req.body;
    const contest = await Contest.findOne({ _id: toObjectId(req.params.id) });
    if (!contest) return res.status(404).json({ message: 'Contest not found' });
    const dbUser = await getDbUserByUid(req.user.uid);
    if (String(contest.creator) !== String(dbUser._id) && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Only creator/admin can declare winner' });
    }
    if (contest.winner && contest.winner.user) {
      return res.status(400).json({ message: 'Winner already declared' });
    }
    if (new Date(contest.deadline) > new Date()) {
      return res.status(400).json({ message: 'Cannot declare winner before deadline' });
    }
    const submission = await Submission.aggregate([
      { $match: { _id: toObjectId(submissionId) } },
      { $lookup: { from: 'users', localField: 'user', foreignField: '_id', as: 'user' } },
      { $unwind: '$user' },
      { $project: { _id: 1, 'user._id': 1 } }
    ]).next();
    if (!submission) return res.status(404).json({ message: 'Submission not found' });

    contest.winner = { user: submission.user._id, submission: submission._id, declaredAt: new Date() };
    await Contest.updateOne({ _id: contest._id }, { $set: { winner: contest.winner } });
    res.json({ message: 'Winner declared', contest });
  } catch (error) {
    res.status(500).json({ message: 'Error declaring winner', error: error.message });
  }
});

app.get('/api/users/:uid/participations', verifyToken, async (req, res) => {
  try {
    if (req.user.uid !== req.params.uid && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const dbUser = await getDbUserByUid(req.params.uid);
    const rows = await Participation.aggregate([
      { $match: { user: dbUser._id, paymentStatus: 'paid' } },
      { $sort: { createdAt: -1 } },
      { $lookup: { from: 'contests', localField: 'contest', foreignField: '_id', as: 'contest' } },
      { $unwind: '$contest' },
      { $lookup: { from: 'users', localField: 'contest.creator', foreignField: '_id', as: 'creator' } },
      { $unwind: '$creator' },
      { $project: { amount: 1, paymentStatus: 1, createdAt: 1, contest: { name: '$contest.name', contestType: '$contest.contestType' }, creator: { displayName: '$creator.displayName', email: '$creator.email' } } }
    ]).toArray();
    res.json(rows);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching participations', error: error.message });
  }
});

app.get('/api/users/:uid/wins', verifyToken, async (req, res) => {
  try {
    if (req.user.uid !== req.params.uid && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const dbUser = await getDbUserByUid(req.params.uid);
    const wins = await Contest.aggregate([
      { $match: { 'winner.user': dbUser._id } },
      { $lookup: { from: 'users', localField: 'creator', foreignField: '_id', as: 'creator' } },
      { $unwind: '$creator' },
      { $lookup: { from: 'users', localField: 'winner.user', foreignField: '_id', as: 'winnerUser' } },
      { $unwind: '$winnerUser' },
      { $project: { name: 1, prizeMoney: 1, image: 1, 'creator.displayName': 1, 'creator.email': 1, 'winnerUser.displayName': 1, 'winnerUser.email': 1, 'winnerUser.photoURL': 1, winner: 1 } }
    ]).toArray();
    res.json(wins);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching wins', error: error.message });
  }
});

app.get('/api/users/:uid/created-contests', verifyToken, async (req, res) => {
  try {
    if (req.user.uid !== req.params.uid && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Forbidden' });
    }
    const dbUser = await getDbUserByUid(req.params.uid);
    const contests = await Contest.find({ creator: dbUser._id }).sort({ createdAt: -1 }).toArray();
    res.json(contests);
  } catch (error) {
    res.status(500).json({ message: 'Error fetching created contests', error: error.message });
  }
});

app.get('/api/leaderboard', async (req, res) => {
  try {
    const agg = await Contest.aggregate([
      { $match: { 'winner.user': { $ne: null } } },
      { $group: { _id: '$winner.user', wins: { $sum: 1 } } },
      { $sort: { wins: -1 } },
      { $limit: 50 }
    ]).toArray();

    const users = await User.find({ _id: { $in: agg.map(a => a._id) } }).project({ displayName: 1, email: 1, photoURL: 1, uid: 1 }).toArray();
    const usersMap = Object.fromEntries(users.map(u => [String(u._id), u]));

    const result = agg.map(a => ({ user: usersMap[String(a._id)], wins: a.wins }));
    res.json(result);
  } catch (error) {
    res.status(500).json({ message: 'Error building leaderboard', error: error.message });
  }
});

app.get('/api/winners/recent', async (req, res) => {
  try {
    const recent = await Contest.aggregate([
      { $match: { 'winner.user': { $ne: null } } },
      { $sort: { 'winner.declaredAt': -1 } },
      { $limit: 10 },
      { $lookup: { from: 'users', localField: 'winner.user', foreignField: '_id', as: 'winnerUser' } },
      { $unwind: '$winnerUser' },
      { $project: { name: 1, prizeMoney: 1, image: 1, winner: 1, declaredAt: 1, 'winnerUser.displayName': 1, 'winnerUser.email': 1, 'winnerUser.photoURL': 1 } }
    ]).toArray();

    const totals = await Contest.aggregate([
      { $match: { 'winner.user': { $ne: null } } },
      { $group: { _id: null, totalWinners: { $sum: 1 }, totalPrize: { $sum: { $ifNull: ['$prizeMoney', 0] } } } }
    ]).toArray();

    const stats = totals[0] || { totalWinners: 0, totalPrize: 0 };

    res.json({ recent, stats });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching recent winners', error: error.message });
  }
});

app.get('/api/contests/:id/registration-status', verifyToken, async (req, res) => {
  try {
    const contest = await Contest.findOne({ _id: toObjectId(req.params.id) });
    if (!contest) return res.status(404).json({ message: 'Contest not found' });
    const dbUser = await getDbUserByUid(req.user.uid);
    if (!dbUser) return res.status(404).json({ message: 'User not found' });

    const part = await Participation.findOne({ user: dbUser._id, contest: contest._id });
    const registered = !!(part && part.paymentStatus === 'paid');
    res.json({ registered, paymentStatus: part?.paymentStatus || 'none' });
  } catch (error) {
    res.status(500).json({ message: 'Error checking registration', error: error.message });
  }
});

app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  res.status(500).json({ message: 'Server error', error: err.message });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port http://localhost:${PORT}`);
});
