# GHOST OSINT CRM - Quick Start Guide

## 🎉 System is Secure and Ready to Use!

Your GHOST OSINT CRM application is now fully secured with authentication on all endpoints.

## Access the Application

**Web Interface:** http://localhost:8080

**Login Credentials:**
- **Username:** `ghost`
- **Password:** `admin123`

## What's Running

- ✅ Frontend (Nginx): http://localhost:8080
- ✅ Backend API (Node.js): http://localhost:3001
- ✅ Database (PostgreSQL): port 5432
- ✅ All services healthy

## Test Data Available

The application includes realistic test data:
- **6 People** - Suspects, witnesses, victims across 3 investigation cases
- **3 Cases** - Cybercrime, corporate espionage, missing person
- **2 Businesses** - Related companies
- **8 OSINT Tools** - Pre-configured tool inventory
- **8 Tasks** - Investigation todos
- **5 Travel History** records

## Key Features to Explore

### 1. People Management
- View all people under investigation
- See detailed profiles with OSINT data
- Track social media, emails, phone numbers
- View connections between people

### 2. Entity Network Visualization
- Navigate to "Entity Network" section
- See interactive relationship diagram
- Explore connections between people
- Click nodes for details

### 3. Global Intelligence Map
- View geographic locations on map
- See clustering of people in La Jolla, San Jose, San Francisco
- Track movement patterns
- Filter by case or person

### 4. Cases
- 3 active investigation cases
- Track people associated with each case
- Manage case status and details

### 5. Businesses
- CyberShield Solutions LLC (suspect company)
- TechCorp Industries (victim company)
- Link businesses to people

### 6. Travel History
- Track international and domestic travel
- Marcus Rivera's Moscow trip
- David Chen's suspicious Austin visit
- Sarah Chen's last known trip to LA

## Security Changes Applied

All API endpoints now require authentication:

### What This Means
- ✅ You must log in to access any data
- ✅ All actions are tracked to your user account
- ✅ Admin-only operations (export, import, settings) are restricted
- ✅ Your investigation data is protected

### Before (VULNERABLE)
Anyone could access or modify data without logging in.

### After (SECURE)
All endpoints require authentication. Only logged-in users can access data.

## Common Tasks

### View Investigation Data
1. Log in at http://localhost:8080
2. Navigate to "People" to see all subjects
3. Click on any person to see full details
4. View "Entity Network" for relationship mapping

### Import Additional Data
1. Go to Settings → Data Management
2. Click "Import Data"
3. Upload a JSON file in the correct format
4. Review preview and confirm

### Export Data
1. Go to Settings → Data Management (admin only)
2. Click "Export Data"
3. Download complete database as JSON

### Add New People
1. Navigate to People section
2. Click "Add Person"
3. Fill in details (OSINT data, connections, locations)
4. Save

### View Audit Logs
1. Navigate to "Audit Logs" section (admin only)
2. See all system changes
3. Filter by user, action, entity type, date range

## Docker Container Management

### View Logs
```bash
# Backend logs
docker-compose logs backend

# Frontend logs
docker-compose logs frontend

# Database logs
docker-compose logs db

# All logs
docker-compose logs
```

### Restart Services
```bash
# Restart all
docker-compose restart

# Restart specific service
docker-compose restart backend
```

### Stop Services
```bash
docker-compose stop
```

### Start Services
```bash
docker-compose up -d
```

### View Running Containers
```bash
docker-compose ps
```

## Troubleshooting

### Can't Login
- Check that backend is running: `docker-compose ps`
- Check backend health: `curl http://localhost:3001/api/health`
- Verify credentials: username `ghost`, password `admin123`

### Audit Logs Empty
- Audit logs track user-initiated changes through the UI
- Import operations may not generate audit entries
- Make a change (edit a person, create a case) to see logs populate

### Forgot Password
```bash
# Reset password
docker exec -it osint-crm-backend node -e "
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const pool = new Pool({
  user: 'postgres', host: 'db',
  database: 'osint_crm_db', password: 'changeme', port: 5432
});
(async () => {
  const hash = await bcrypt.hash('newpassword', 10);
  await pool.query('UPDATE users SET password_hash = \$1 WHERE username = \$2', [hash, 'ghost']);
  console.log('Password reset to: newpassword');
  await pool.end();
})();
"
```

### Frontend Not Loading
- Check if port 8080 is available: `lsof -i :8080`
- Check frontend logs: `docker-compose logs frontend`
- Try clearing browser cache

### API Not Responding
- Check backend health: `curl http://localhost:3001/api/health`
- Check backend logs: `docker-compose logs backend`
- Ensure database is connected

## API Access (For Developers)

If you need to access the API programmatically:

```bash
# Step 1: Login
curl -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"ghost","password":"admin123"}' \
  -c cookies.txt

# Step 2: Make authenticated requests
curl -b cookies.txt http://localhost:3001/api/people
curl -b cookies.txt http://localhost:3001/api/cases
curl -b cookies.txt http://localhost:3001/api/businesses
```

## User Management

### Create Additional Users
1. Log in as admin (ghost)
2. Navigate to Settings → User Management
3. Click "Add User"
4. Set username, password, role (admin/user)

### Via Command Line
```bash
docker exec -it osint-crm-backend node scripts/createAdminUser.js
```

## Production Deployment Notes

⚠️ **Before deploying to production:**

1. **Change default password** for ghost user
2. **Generate secure SESSION_SECRET**: `openssl rand -base64 32`
3. **Set strong DB_PASSWORD**
4. **Configure FRONTEND_URL** in .env
5. **Enable HTTPS** with valid SSL certificate
6. **Don't expose database port** externally
7. **Use firewall** to restrict access to necessary ports only
8. **Regular backups** of PostgreSQL database
9. **Monitor logs** for suspicious activity
10. **Keep dependencies updated**

## Files for Reference

- **SECURITY-STATUS.md** - Current security status (all secure)
- **SECURITY-FIX-SUMMARY.md** - Detailed fix documentation
- **SECURITY-AUDIT.md** - Original vulnerability report
- **TEST-DATA-README.md** - Test data documentation
- **README.md** - Full application documentation
- **CHANGELOG.md** - Version history

## Support

For issues:
1. Check logs: `docker-compose logs`
2. Check health: `curl http://localhost:3001/api/health`
3. Review documentation files above
4. Open issue on GitHub repository

## Next Steps

1. **Explore the test data** - Navigate through people, cases, network diagram
2. **Try the map view** - See geographic distribution of investigation subjects
3. **Check entity relationships** - View the interactive network diagram
4. **Review travel history** - Track subject movements
5. **Add your own data** - Create new people, cases, businesses

---

**Status:** ✅ All systems operational and secure
**Documentation:** Complete
**Test Data:** Loaded
**Security:** Verified
**Ready for:** Investigation work

Enjoy using GHOST OSINT CRM! 🕵️
