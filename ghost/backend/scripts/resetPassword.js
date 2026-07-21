#!/usr/bin/env node

// Script to reset a user's password
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const readline = require('readline');

// Determine database host based on environment
const dbConfig = {
  user: process.env.DB_USER || 'postgres',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'osint_crm_db',
  password: process.env.DB_PASSWORD || 'changeme',
  port: parseInt(process.env.DB_PORT || '5432', 10),
};

const pool = new Pool(dbConfig);

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const question = (query) => new Promise((resolve) => rl.question(query, resolve));

async function resetPassword() {
  console.log('\n=== Reset User Password ===\n');

  try {
    // Test database connection
    console.log('Testing database connection...');
    await pool.query('SELECT NOW()');
    console.log('✓ Database connection successful\n');

    // List existing users
    const users = await pool.query('SELECT id, username, email, role FROM users ORDER BY id');

    if (users.rows.length === 0) {
      console.log('No users found in database.');
      console.log('Run: docker exec -it osint-crm-backend node scripts/createAdminUser.js');
      process.exit(0);
    }

    console.log('Existing users:');
    users.rows.forEach(user => {
      console.log(`  [${user.id}] ${user.username} (${user.role})${user.email ? ' - ' + user.email : ''}`);
    });
    console.log();

    // Get username
    const username = await question('Enter username to reset password: ');
    if (!username) {
      console.error('Error: Username is required');
      process.exit(1);
    }

    // Check if user exists
    const userCheck = await pool.query('SELECT id, username, role FROM users WHERE username = $1', [username]);
    if (userCheck.rows.length === 0) {
      console.error(`Error: User "${username}" not found`);
      process.exit(1);
    }

    const user = userCheck.rows[0];
    console.log(`\nFound user: ${user.username} (${user.role})`);

    // Get new password
    const password = await question('New password: ');
    if (!password) {
      console.error('Error: Password is required');
      process.exit(1);
    }

    if (password.length < 6) {
      console.error('Error: Password must be at least 6 characters');
      process.exit(1);
    }

    // Hash password
    console.log('\nUpdating password...');
    const password_hash = await bcrypt.hash(password, 10);

    // Update password
    await pool.query(
      'UPDATE users SET password_hash = $1, updated_at = NOW() WHERE username = $2',
      [password_hash, username]
    );

    console.log('\n✓ Password reset successfully!\n');
    console.log(`You can now log in as "${username}" with the new password.\n`);

  } catch (error) {
    console.error('\n✗ Error resetting password:', error.message);
    process.exit(1);
  } finally {
    rl.close();
    await pool.end();
  }
}

resetPassword();
