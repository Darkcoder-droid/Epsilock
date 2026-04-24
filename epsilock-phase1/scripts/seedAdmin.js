const path = require('path');
const bcrypt = require('bcryptjs');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { connectDB } = require('../shared/db');
const User = require('../shared/models/User');

async function run() {
  await connectDB();

  const username = 'admin';
  const password = 'admin123';

  const existing = await User.findOne({ username, role: 'admin' });
  if (existing) {
    console.log('Admin already exists');
    process.exit(0);
  }

  const passwordHash = await bcrypt.hash(password, 12);
  await User.create({
    username,
    passwordHash,
    role: 'admin',
    assignedNodeType: null,
    assignedNodeId: null
  });

  console.log('Seeded admin account: admin / admin123');
  process.exit(0);
}

run().catch((err) => {
  console.error('Seed failed', err);
  process.exit(1);
});
