const path = require('path');
const bcrypt = require('bcryptjs');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const { connectDB } = require('../config/db');
const User = require('../models/User');

async function run() {
  await connectDB();

  const username = 'admin';
  const password = 'admin123';

  const exists = await User.findOne({ username, role: 'admin' });
  if (exists) {
    console.log('Admin already exists');
    process.exit(0);
  }

  const passwordHash = await bcrypt.hash(password, 12);
  await User.create({ username, passwordHash, role: 'admin' });
  console.log('Seeded admin: admin / admin123');
  process.exit(0);
}

run().catch((err) => {
  console.error(err);
  process.exit(1);
});
