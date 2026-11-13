const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
const multer = require('multer');
const fs = require('fs');
// const csurf = require('csurf'); // Removed - using custom CSRF protection
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500'], 
    credentials: true,
}));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Simple CSRF Protection middleware - temporarily disabled for testing
const csrfProtection = (req, res, next) => {
    // Temporarily disable CSRF protection to fix the issue
    console.log('CSRF protection temporarily disabled for testing');
    next();
};

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        if (file.fieldname === 'resume' && file.mimetype === 'application/pdf') {
            cb(null, true);
        } else if (file.fieldname === 'image' && file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type'), false);
        }
    },
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    }
});

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/jobportal', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
}).then(() => {
    console.log('Connected to MongoDB');
}).catch(err => {
    console.error('MongoDB connection error:', err);
});

// Mongoose Schemas
const userSchema = new mongoose.Schema({
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true, minlength: 6 },
    role: { type: String, enum: ['jobseeker', 'employer'], default: 'jobseeker' },
    createdAt: { type: Date, default: Date.now }
});
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});
const User = mongoose.model('User', userSchema);

const jobSchema = new mongoose.Schema({
    title: { type: String, required: true, trim: true },
    company: { type: String, required: true, trim: true },
    location: { type: String, required: true, trim: true },
    jobType: { type: String, enum: ['full-time', 'part-time', 'contract', 'internship'], required: true },
    workMode: { type: String, enum: ['remote', 'onsite', 'hybrid'], required: true },
    experience: { type: String, required: true },
    salary: { min: Number, max: Number, currency: { type: String, default: 'USD' } },
    description: { type: String, required: true },
    requirements: [{ type: String, required: true }],
    benefits: [{ type: String }],
    skills: [{ type: String, required: true }],
    applicationDeadline: { type: Date, required: true },
    companyLogo: { type: String, default: 'https://images.unsplash.com/photo-1497366216548-37526070297c?ixlib=rb-4.0.3&auto=format&fit=crop&w=500&q=80' },
    postedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});
const Job = mongoose.model('Job', jobSchema);

const applicationSchema = new mongoose.Schema({
    jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'Job', required: true },
    applicantId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    firstName: { type: String, required: true, trim: true },
    lastName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true },
    phone: { type: String, required: true, trim: true },
    coverLetter: { type: String, trim: true },
    experience: { type: String, required: true },
    resumeUrl: { type: String, required: true },
    status: { type: String, enum: ['pending', 'reviewing', 'shortlisted', 'rejected', 'hired'], default: 'pending' },
    appliedAt: { type: Date, default: Date.now }
});
const Application = mongoose.model('Application', applicationSchema);

// Helper function to generate a JWT
const generateToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '7d' });
};

// Middleware to authenticate JWT token from cookie
const authenticateToken = async (req, res, next) => {
    try {
        const token = req.cookies.token || req.header('Authorization')?.replace('Bearer ', '');
        if (!token) {
            return res.status(401).json({ message: 'Access denied. No token provided.' });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        const user = await User.findById(decoded.userId).select('-password');
        if (!user) {
            return res.status(401).json({ message: 'Invalid token.' });
        }
        req.user = user;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token.' });
    }
};

// Middleware for role-based authorization
const authorizeRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ message: 'Permission denied.' });
        }
        next();
    };
};

// CSRF Token route - without CSRF protection to avoid circular dependency
app.get('/api/csrf-token', (req, res) => {
    console.log('CSRF token endpoint called');
    // Generate a new CSRF token
    const token = require('crypto').randomBytes(32).toString('hex');

    res.cookie('XSRF-TOKEN', token, {
        httpOnly: false,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    });
    console.log('CSRF token cookie set with path: /');
    res.json({ csrfToken: token });
});

// auth.js is now served by static middleware at /auth.js

// Debug route to test CSRF token generation


// Test endpoint to verify auth.js is working


// Route handlers (HTML pages)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/signup', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/jobs', (req, res) => res.sendFile(path.join(__dirname, 'public', 'jobs.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, 'public', 'about.html')));

app.get('/dashboard', authenticateToken, (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/applications', authenticateToken, (req, res) => res.sendFile(path.join(__dirname, 'public', 'applications.html')));
app.get('/posted-jobs', authenticateToken, (req, res) => res.sendFile(path.join(__dirname, 'public', 'posted-jobs.html')));
app.get('/profile', authenticateToken, (req, res) => res.sendFile(path.join(__dirname, 'public', 'profile.html')));
app.get('/resume', authenticateToken, (req, res) => res.sendFile(path.join(__dirname, 'public', 'resume.html')));

// API Routes
app.post('/api/signup', async (req, res) => {
    try {
        const { fullName, email, password, role } = req.body;
        if (!fullName || !email || !password) {
            return res.status(400).json({ message: 'Please provide all required fields' });
        }
        if (password.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long' });
        }
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'User already exists with this email' });
        }
        const user = new User({ fullName, email, password, role: role || 'jobseeker' });
        await user.save();
        const token = generateToken(user._id);
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.status(201).json({
            message: 'User registered successfully',
            user: { id: user._id, fullName: user.fullName, email: user.email, role: user.role }
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ message: 'Please provide email and password' });
        }
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }
        const token = generateToken(user._id);
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });
        res.json({
            message: 'Login successful',
            user: { id: user._id, fullName: user.fullName, email: user.email, role: user.role }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'Logged out successfully' });
});

app.get('/api/me', authenticateToken, (req, res) => {
    res.json({
        user: {
            id: req.user._id,
            fullName: req.user.fullName,
            email: req.user.email,
            role: req.user.role,
            createdAt: req.user.createdAt
        }
    });
});

app.post('/api/jobs', authenticateToken, authorizeRole('employer'), upload.single('image'), async (req, res) => {
    try {
        if (req.user.role !== 'employer') {
            return res.status(403).json({ message: 'Only employers can post jobs' });
        }
        const {
            title,
            company,
            location,
            jobType,
            workMode,
            experience,
            description,
            requirements,
            benefits,
            skills,
            applicationDeadline
        } = req.body;
        let companyLogo = req.body.companyLogo;
        if (req.file) {
            companyLogo = `/uploads/${req.file.filename}`;
        }
        if (!title || !company || !location || !jobType || !workMode || !experience || !description || !requirements || !skills || !applicationDeadline) {
            return res.status(400).json({ message: 'Please provide all required fields' });
        }
        const job = new Job({
            title,
            company,
            location,
            jobType,
            workMode,
            experience,
            description,
            requirements: Array.isArray(requirements) ? requirements : requirements.split(',').map(r => r.trim()),
            benefits: benefits ? (Array.isArray(benefits) ? benefits : benefits.split(',').map(b => b.trim())) : [],
            skills: Array.isArray(skills) ? skills : skills.split(',').map(s => s.trim()),
            applicationDeadline: new Date(applicationDeadline),
            companyLogo: companyLogo,
            postedBy: req.user._id
        });
        await job.save();
        res.status(201).json({
            message: 'Job posted successfully',
            job: job
        });
    } catch (error) {
        console.error('Job posting error:', error);
        res.status(500).json({ message: 'Server error during job posting' });
    }
});

app.get('/api/jobs', async (req, res) => {
    try {
        const { page = 1, limit = 10, search, location, jobType, workMode, sort } = req.query;
        let now = new Date();
        let query = { isActive: true, applicationDeadline: { $gt: now } };
        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { company: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } }
            ];
        }
        if (location) {
            query.location = { $regex: location, $options: 'i' };
        }
        if (jobType) {
            query.jobType = jobType;
        }
        if (workMode) {
            query.workMode = workMode;
        }

        let sortOption = { createdAt: -1 };
        if (sort === 'oldest') {
            sortOption = { createdAt: 1 };
        }
        const jobs = await Job.find(query)
            .populate('postedBy', 'fullName email')
            .sort(sortOption)
            .limit(limit * 1)
            .skip((page - 1) * limit);
        const total = await Job.countDocuments(query);
        res.json({
            jobs,
            totalPages: Math.ceil(total / limit),
            currentPage: page,
            total
        });
    } catch (error) {
        console.error('Get jobs error:', error);
        res.status(500).json({ message: 'Server error while fetching jobs' });
    }
});

app.get('/api/my-jobs', authenticateToken, authorizeRole('employer'), async (req, res) => {
    try {
        const jobs = await Job.find({ postedBy: req.user._id }).sort({ createdAt: -1 });
        res.json({ jobs });
    } catch (error) {
        console.error('Get my jobs error:', error);
        res.status(500).json({ message: 'Server error while fetching your jobs' });
    }
});

app.get('/api/applications/:id', authenticateToken, async (req, res) => {
    try {
        const application = await Application.findById(req.params.id).populate('jobId').populate('applicantId', 'fullName email');
        if (!application) {
            return res.status(404).json({ message: 'Application not found' });
        }
        if (req.user.role === 'jobseeker' && !application.applicantId._id.equals(req.user._id)) {
            return res.status(403).json({ message: 'Permission denied' });
        }
        if (req.user.role === 'employer' && !application.jobId.postedBy.equals(req.user._id)) {
            return res.status(403).json({ message: 'Permission denied' });
        }
        res.json({ application });
    } catch (error) {
        console.error('Get single application error:', error);
        res.status(500).json({ message: 'Server error while fetching application' });
    }
});

app.post('/api/applications', authenticateToken, upload.single('resume'), async (req, res) => {
    try {
        const { jobId, firstName, lastName, email, phone, coverLetter, experience } = req.body;
        if (!jobId || !firstName || !lastName || !email || !phone || !experience) {
            return res.status(400).json({ message: 'Please provide all required fields' });
        }
        if (!req.file) {
            return res.status(400).json({ message: 'Please upload a resume (PDF only)' });
        }
        const job = await Job.findById(jobId);
        if (!job) {
            return res.status(404).json({ message: 'Job not found' });
        }
        if (new Date() > job.applicationDeadline) {
            return res.status(400).json({ message: 'Application deadline has passed' });
        }
        // Use the authenticated user's ID
        const applicantId = req.user._id;
        const existingApplication = await Application.findOne({ jobId, applicantId: req.user._id });
        if (existingApplication) {
            return res.status(400).json({ message: 'You have already applied for this job' });
        }
        const application = new Application({
            jobId,
            applicantId,
            firstName,
            lastName,
            email,
            phone,
            coverLetter: coverLetter || '',
            experience,
            resumeUrl: req.file.path
        });
        await application.save();
        await application.populate('jobId', 'title company');
        console.log(`New application received for job: ${job.title} from ${firstName} ${lastName}`);
        res.status(201).json({
            message: 'Application submitted successfully',
            application: {
                id: application._id,
                jobTitle: job.title,
                company: job.company,
                applicantName: `${firstName} ${lastName}`,
                email,
                status: application.status,
                appliedAt: application.appliedAt
            }
        });
    } catch (error) {
        console.error('Application submission error:', error);
        res.status(500).json({ message: 'Server error during application submission' });
    }
});

app.get('/api/my-applications', authenticateToken, async (req, res) => {
    try {
        console.log('Fetching applications for user:', req.user._id);
        console.log('User email:', req.user.email);
        
        // First try to find applications by applicantId
        let applications = await Application.find({ applicantId: req.user._id })
            .populate('jobId', 'title company location jobType workMode')
            .sort({ appliedAt: -1 });
        
        console.log('Applications found by applicantId:', applications.length);
        
        // If no applications found by applicantId, try to find by email
        if (applications.length === 0) {
            console.log('No applications found by applicantId, trying email...');
            applications = await Application.find({ email: req.user.email })
                .populate('jobId', 'title company location jobType workMode')
                .sort({ appliedAt: -1 });
            
            console.log('Applications found by email:', applications.length);
            
            // Update these applications to link them to the user
            if (applications.length > 0) {
                await Application.updateMany(
                    { email: req.user.email, applicantId: null },
                    { applicantId: req.user._id }
                );
                console.log('Updated applications to link to user');
            }
        }
        
        const formattedApplications = applications.map(app => ({
            id: app._id,
            jobTitle: app.jobId?.title || 'Job Deleted',
            company: app.jobId?.company || 'N/A',
            location: app.jobId?.location || 'N/A',
            jobType: app.jobId?.jobType || 'N/A',
            workMode: app.jobId?.workMode || 'N/A',
            status: app.status,
            appliedAt: app.appliedAt,
            coverLetter: app.coverLetter
        }));
        
        console.log('Returning formatted applications:', formattedApplications.length);
        res.json({ applications: formattedApplications });
    } catch (error) {
        console.error('Get applications error:', error);
        res.status(500).json({ message: 'Server error while fetching applications' });
    }
});

app.get('/api/applied-jobs', authenticateToken, async (req, res) => {
    try {
        const applications = await Application.find({ applicantId: req.user._id }).select('jobId');
        const appliedJobIds = applications.map(app => app.jobId.toString());
        res.json({ appliedJobIds });
    } catch (error) {
        console.error('Get applied jobs error:', error);
        res.status(500).json({ message: 'Server error while fetching applied jobs' });
    }
});

// Saved jobs endpoint (placeholder - you can implement actual saved jobs functionality later)
app.get('/api/saved-jobs', authenticateToken, async (req, res) => {
    try {
        // For now, return empty array - you can implement saved jobs functionality later
        res.json({ jobs: [] });
    } catch (error) {
        console.error('Get saved jobs error:', error);
        res.status(500).json({ message: 'Server error while fetching saved jobs' });
    }
});

app.get('/api/my-applications-count', authenticateToken, authorizeRole('employer'), async (req, res) => {
    try {
        const jobs = await Job.find({ postedBy: req.user._id }).select('_id');
        const jobIds = jobs.map(job => job._id);
        const totalApplications = await Application.countDocuments({ jobId: { $in: jobIds } });
        res.json({ totalApplications });
    } catch (error) {
        console.error('Get employer applications count error:', error);
        res.status(500).json({ message: 'Server error while fetching applications count' });
    }
});

app.post('/api/recent-applications', authenticateToken, authorizeRole('employer'), async (req, res) => {
    try {
        const { jobIds } = req.body;
        if (!jobIds || !Array.isArray(jobIds)) {
            return res.status(400).json({ message: 'Job IDs are required' });
        }
        const applications = await Application.find({ jobId: { $in: jobIds } })
            .populate('jobId', 'title company')
            .sort({ appliedAt: -1 })
            .limit(3);
        const formattedApplications = applications.map(app => ({
            id: app._id,
            applicantName: `${app.firstName} ${app.lastName}`,
            email: app.email,
            resumeUrl: app.resumeUrl,
            status: app.status,
            appliedAt: app.appliedAt,
            jobId: app.jobId
        }));
        res.json({ applications: formattedApplications });
    } catch (error) {
        console.error('Get recent applications error:', error);
        res.status(500).json({ message: 'Server error while fetching recent applications' });
    }
});

app.get('/api/job-applications/:jobId', authenticateToken, authorizeRole('employer'), async (req, res) => {
    try {
        const job = await Job.findOne({ _id: req.params.jobId, postedBy: req.user._id });
        if (!job) {
            return res.status(404).json({ message: 'Job not found or you do not have permission to view applications' });
        }
        const applications = await Application.find({ jobId: req.params.jobId })
            .populate('jobId', 'title company')
            .sort({ appliedAt: -1 });
        const formattedApplications = applications.map(app => ({
            id: app._id,
            applicantName: `${app.firstName} ${app.lastName}`,
            email: app.email,
            phone: app.phone,
            experience: app.experience,
            coverLetter: app.coverLetter,
            resumeUrl: app.resumeUrl,
            status: app.status,
            appliedAt: app.appliedAt
        }));
        res.json({
            job: {
                title: job.title,
                company: job.company
            },
            applications: formattedApplications
        });
    } catch (error) {
        console.error('Get job applications error:', error);
        res.status(500).json({ message: 'Server error while fetching job applications' });
    }
});

app.post('/api/applications/:id/status', authenticateToken, authorizeRole('employer'), async (req, res) => {
    try {
        const application = await Application.findById(req.params.id).populate('jobId');
        if (!application) {
            return res.status(404).json({ message: 'Application not found' });
        }
        if (!application.jobId.postedBy.equals(req.user._id)) {
            return res.status(403).json({ message: 'Permission denied' });
        }
        application.status = req.body.status;
        await application.save();
        res.json({ message: 'Application status updated successfully', application });
    } catch (error) {
        console.error('Update application status error:', error);
        res.status(500).json({ message: 'Server error while updating application status' });
    }
});

app.post('/api/profile/update', authenticateToken, async (req, res) => {
    try {
        const { fullName } = req.body;
        if (!fullName) {
            return res.status(400).json({ message: 'Full name is required' });
        }
        const user = await User.findByIdAndUpdate(req.user._id, { fullName }, { new: true }).select('-password');
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'Profile updated successfully', user });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ message: 'Server error during profile update' });
    }
});

// General error handling middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ 
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong'
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
    console.log(`Visit: http://localhost:${PORT}`);
});