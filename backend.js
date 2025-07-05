// backend.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const AWS = require('aws-sdk');
const nodemailer = require('nodemailer');
require('dotenv').config();
const baseURL = process.env.BASE_URL || 'http://localhost:5000';

AWS.config.update({
    region: 'ap-south-1', // IMPORTANT: This region must match where your DynamoDB tables are located.
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || 'AKIAVEP3EDM5K3LA5J47', // Use env var or provided key
    secretAccessKey: process.env.AWS_ACCESS_KEY_ID || 'YfIszgolrWKUglxC6Q85HSb3V0qhDsa00yv6jcIP' // Use env var or provided key
});

const dynamodb = new AWS.DynamoDB.DocumentClient();

// --- Nodemailer Transporter for GMAIL SMTP (using your App Password) ---
const gmailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'craids22@gmail.com', // <--- REPLACE THIS with YOUR GMAIL ADDRESS
        pass: 'opok nwqf kukx aihh' // <--- YOUR GENERATED APP PASSWORD
    }
});

// --- Constants ---
const JWT_SECRET = 'jwt_secret_key_54742384238423_ahfgrdtTFHHYJNMP[]yigfgfjdfjd=-+&+pqiel;,,dkvntegdv/cv,mbkzmbzbhsbha#&$^&(#_enD';
const PORT = 5000;
const USER_TABLE_NAME = 'Usertable';
const TEST_ATTEMPTS_TABLE_NAME = 'TestAttempts';
const COURSE_PROGRESS_TABLE = 'CourseProgress';
const VIOLATIONS_TABLE_NAME = 'ViolationsTable';
const PASSWORD_RESET_TABLE_NAME = 'PasswordResetTokens'; // NEW: Table for password reset tokens
const PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES = 60; // NEW: Token valid for 60 minutes


const ALL_QUESTIONS_DATA = require('./questions.json');

const NUMBER_OF_QUESTIONS_PER_TEST = 25;
const NUMBER_OF_MODULES = 14;

// --- Express App Setup ---
const app = express();
app.use(cors({
    origin: ['http://localhost:3000', `http://localhost:${PORT}`, `http://127.0.0.1:${PORT}`]
}));
app.use(bodyParser.json());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (HTML pages)
app.use(express.static(path.join(__dirname)));
app.get('/Login', (req, res) => res.sendFile(path.join(__dirname, 'Login.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'Login.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/Login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));

app.get('/Signup', (req, res) => res.sendFile(path.join(__dirname, 'Signup.html')));
app.get('/home', (req, res) => res.sendFile(path.join(__dirname, 'Home.html')));
app.get('/test', (req, res) => res.sendFile(path.join(__dirname, 'Test.html')));
app.get('/certificate', (req, res) => res.sendFile(path.join(__dirname, 'Certificate.html')));
app.get('/welcome', (req, res) => res.sendFile(path.join(__dirname, 'welcome.html')));
app.get('/Course', (req, res) => res.sendFile(path.join(__dirname, 'Course.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'Admin.html')));
app.use('/pdfs', express.static(path.join(__dirname, 'PPts')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'welcome.html')));

// NEW: Routes for Forgot/Reset Password HTML
app.get('/forgot-password', (req, res) => res.sendFile(path.join(__dirname, 'forgot-password.html')));
app.get('/reset-password', (req, res) => res.sendFile(path.join(__dirname, 'reset-password.html')));

function generateOtp() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}
// END ADD FUNCTION

// Utility function to send email
// ADD THIS FUNCTION
async function sendEmail(to, subject, text, html) {
    const mailOptions = {
        from: process.env.GMAIL_USER,
        to,
        subject,
        text,
        html
    };

    try {
        await gmailTransporter.sendMail(mailOptions);
        console.log(`Email sent successfully to ${to}`);
    } catch (error) {
        console.error(`Error sending email to ${to}:`, error);
        throw new Error('Failed to send email.');
    }
}


// --- Helper Function for DynamoDB Checks (used in signup) ---
async function checkIfAttributeExists(tableName, indexName, attributeName, value) {
    const params = {
        TableName: tableName,
        IndexName: indexName,
        KeyConditionExpression: `${attributeName} = :value`,
        ExpressionAttributeValues: { ':value': value },
        ProjectionExpression: attributeName,
        Limit: 1
    };
    try {
        const result = await dynamodb.query(params).promise();
        return result.Items && result.Items.length > 0;
    } catch (error) {
        console.error(`Error checking if attribute exists in ${tableName} (${indexName}):`, error);
        throw error;
    }
}

// --- User Authentication Middleware ---
// --- User Authentication Middleware ---
function authenticateUser(req, res, next) {
    const authHeader = req.headers.authorization;
    console.log('SERVER DEBUG: authenticateUser called. Authorization header:', authHeader);
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('SERVER DEBUG: Auth header missing or malformed.');
        return res.status(401).json({ message: 'Authorization token not provided or malformed.' });
    }
    const token = authHeader.replace('Bearer ', '');
    console.log('SERVER DEBUG: Token extracted (first 20 chars):', token.substring(0, 20) + '...');
    try {
        // --- CHANGE: Corrected SECRET_KEY to JWT_SECRET ---
        const decoded = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        console.log('SERVER DEBUG: Token decoded successfully. User ID:', decoded.userId, 'Role:', decoded.role);
        req.user = decoded; // Attach user info to request
        next();
    } catch (error) {
        console.error('SERVER ERROR: JWT Verification FAILED:', error.message, 'Name:', error.name);
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired. Please log in again.' });
        } else if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Invalid token. Please log in again.' });
        } else {
            return res.status(500).json({ message: 'Authentication failed due to an unexpected error.' });
        }
    }
}


// --- Admin Authorization Middleware ---
function authorizeAdmin(req, res, next) {
    console.log('SERVER DEBUG: authorizeAdmin called. User role:', req.user ? req.user.role : 'N/A');
    if (req.user && req.user.role === 'admin') {
        next(); // User is an admin, proceed
    } else {
        console.warn('SERVER DEBUG: Admin authorization failed.');
        return res.status(403).json({ message: 'Access denied. Administrator privileges required.' });
    }
}


// --- Signup Route ---
// MODIFIED: Endpoint for initial signup (sends OTP)
app.post('/signup', async (req, res) => {
    const { username, email, mobile, password, collegeName } = req.body;

    if (!username || !email || !mobile || !password || !collegeName) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        // Check if user already exists (by email)
        const userParams = {
            TableName: 'Usertable',
            KeyConditionExpression: 'email = :email',
            ExpressionAttributeValues: {
                ':email': email,
            },
            IndexName: 'EmailIndex' // Assuming you have a GSI on email
        };
        const existingUser = await dynamodb.query(userParams).promise();

        let userId;
        let otp = generateOtp(); // ADD THIS
        let otpExpiry = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // OTP valid for 10 minutes // ADD THIS

        if (existingUser.Items.length > 0) {
            // User exists. If status is pending, update OTP. If active, reject.
            const user = existingUser.Items[0];
            if (user.status === 'active') { // MODIFIED: Check status
                return res.status(409).json({ message: 'User with this email already exists and is active. Please log in.' });
            } else if (user.status === 'pending_otp_verification') { // MODIFIED: Handle pending
                // Update existing pending user with new OTP
                userId = user.UserId;
                const updateParams = {
                    TableName: 'Usertable',
                    Key: { 'UserId': userId }, // Assuming UserId is the primary key
                    UpdateExpression: 'set otp = :o, otpExpiry = :oe', // MODIFIED: Add otp and otpExpiry
                    ExpressionAttributeValues: {
                        ':o': otp,
                        ':oe': otpExpiry
                    },
                    ReturnValues: 'UPDATED_NEW'
                };
                await dynamodb.update(updateParams).promise();
                console.log(`Updated OTP for existing pending user: ${email}`);
            }
        } else {
            // New user - create pending entry
            userId = uuidv4();
            const hashedPassword = await bcrypt.hash(password, 10);
            const putParams = {
                TableName: 'Usertable',
                Item: {
                    UserId: userId,
                    username,
                    email,
                    mobile,
                    password: hashedPassword,
                    collegeName,
                    status: 'pending_otp_verification', // ADDED: New status
                    otp: otp, // ADDED: Store OTP
                    otpExpiry: otpExpiry, // ADDED: Store OTP expiry
                    isAdmin: false // Default to false
                }
            };
            await dynamodb.put(putParams).promise();
            console.log(`Created new pending user: ${email}`);
        }

        // Send OTP email // ADD THIS BLOCK
        await sendEmail(
            email,
            'AWSPrepZone - Verify Your Account',
            `Your OTP for AWSPrepZone signup is: ${otp}. It is valid for 10 minutes.`,
            `<p>Your OTP for AWSPrepZone signup is: <strong>${otp}</strong>.</p><p>It is valid for 10 minutes.</p><p>If you did not request this, please ignore this email.</p>`
        );
        // END ADD BLOCK

        // MODIFIED: Response message
        res.status(200).json({ message: 'OTP sent to your email. Please verify to complete signup.' });

    } catch (error) {
        console.error('Error during signup process:', error);
        res.status(500).json({ message: 'Signup failed. Please try again later.' });
    }
});

// NEW: Endpoint to verify OTP and complete signup
app.post('/verify-signup-otp', async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({ message: 'Email and OTP are required.' });
    }

    try {
        const userParams = {
            TableName: 'Usertable',
            KeyConditionExpression: 'email = :email',
            ExpressionAttributeValues: {
                ':email': email,
            },
            IndexName: 'EmailIndex'
        };
        const result = await dynamodb.query(userParams).promise();

        if (result.Items.length === 0) {
            return res.status(404).json({ message: 'User not found or signup process not initiated.' });
        }

        const user = result.Items[0];

        if (user.status !== 'pending_otp_verification') {
            return res.status(400).json({ message: 'Account already active or no pending verification.' });
        }

        // Check OTP and expiry
        if (user.otp !== otp) {
            return res.status(400).json({ message: 'Invalid OTP.' });
        }
        if (new Date() > new Date(user.otpExpiry)) {
            // If OTP expired, optionally clear OTP/expiry and change status for resend flow
            return res.status(400).json({ message: 'OTP expired. Please request a new OTP.' });
        }

        // OTP is valid and not expired, activate account
        const updateParams = {
            TableName: 'Usertable',
            Key: { 'UserId': user.UserId }, // Use the actual primary key
            UpdateExpression: 'set #s = :s remove otp, otpExpiry',
            ExpressionAttributeNames: {
                '#s': 'status'
            },
            ExpressionAttributeValues: {
                ':s': 'active'
            },
            ReturnValues: 'UPDATED_NEW'
        };
        await dynamodb.update(updateParams).promise();

        res.status(200).json({ message: 'Account successfully verified and created!' });

    } catch (error) {
        console.error('Error during OTP verification:', error);
        res.status(500).json({ message: 'OTP verification failed. Please try again later.' });
    }
});
// --- Login Route ---

// MODIFIED: Login Endpoint (checks for 'active' status)
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const params = {
            TableName: 'Usertable',
            KeyConditionExpression: 'email = :email',
            ExpressionAttributeValues: {
                ':email': email,
            },
            IndexName: 'EmailIndex' // Ensure you have a GSI on email for efficient lookup
        };

        const result = await dynamodb.query(params).promise();

        if (result.Items.length === 0) {
            return res.status(401).json({ message: 'User not found.' });
        }

        const user = result.Items[0];

        // Check user status - only active users can log in // ADD THIS BLOCK
        if (user.status !== 'active') {
            if (user.status === 'pending_otp_verification') {
                return res.status(403).json({ message: 'Account pending verification. Please check your email for OTP.' });
            }
            return res.status(403).json({ message: 'Account not active. Please contact support.' });
        }
        // END ADD BLOCK

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        const token = jwt.sign(
    { userId: user.UserId, username: user.username, isAdmin: user.isAdmin, email: user.email, role: user.role }, // <-- IMPORTANT: Ensure role is here
    JWT_SECRET,
    { expiresIn: '1h' }
);

        res.status(200).json({ message: 'Login successful', token, isAdmin: user.isAdmin, username: user.username, email: user.email });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'An error occurred during login.' });
    }
});
// --- Validate Token Route ---
app.get('/validate-token', authenticateUser, (req, res) => {
    res.status(200).json({ message: 'Token is valid', user: req.user });
});

// --- Start Test Route ---
app.get('/start-test', authenticateUser, (req, res) => {
    try {
        const moduleName = req.query.module;
        let questionsToUse = [];

        if (!moduleName) {
            return res.status(400).json({ message: 'Module name is required to start a test.' });
        }

        if (moduleName === "All Modules") {
            questionsToUse = [...ALL_QUESTIONS_DATA];
        } else {
            const moduleNumberMatch = moduleName.match(/Module (\d+)/);
            let selectedModuleNumber = null;
            if (moduleNumberMatch && moduleNumberMatch[1]) {
                selectedModuleNumber = parseInt(moduleNumberMatch[1]);
            }

            if (isNaN(selectedModuleNumber) || selectedModuleNumber < 1 || selectedModuleNumber > NUMBER_OF_MODULES) {
                return res.status(400).json({ message: `Invalid module name: ${moduleName}. Please select a valid module (e.g., "Module 1" to "Module ${NUMBER_OF_MODULES}" or "All Modules").` });
            }

            // Correctly calculate startIndex and endIndex based on ALL_QUESTIONS_DATA being flat
            // Assuming ALL_QUESTIONS_DATA has questions sequentially for modules 1, 2, ...
            const startIndex = (selectedModuleNumber - 1) * NUMBER_OF_QUESTIONS_PER_TEST;
            const endIndex = startIndex + NUMBER_OF_QUESTIONS_PER_TEST;

            questionsToUse = ALL_QUESTIONS_DATA.slice(startIndex, endIndex);
        }

        if (questionsToUse.length === 0) {
            console.warn(`No questions found for ${moduleName}. Total questions: ${ALL_QUESTIONS_DATA.length}`);
            return res.status(404).json({ message: `No questions found for ${moduleName}. Please ensure questions.json has enough questions for this module or the "All Modules" option.` });
        }

        const shuffledQuestions = [...questionsToUse].sort(() => 0.5 - Math.random());
        const finalQuestions = shuffledQuestions.slice(0, NUMBER_OF_QUESTIONS_PER_TEST);

        // MODIFIED: Send the full question objects including correctAnswerIndex
        res.status(200).json({ questions: finalQuestions, moduleTested: moduleName });

    } catch (error) {
        console.error('Error selecting questions:', error);
        res.status(500).json({ message: 'Failed to retrieve test questions.' });
    }
});

// --- NEW: Email Sending Function for Test Completion ---
async function sendTestCompletionEmail(toEmail, username, score, totalQuestions, isPass, module) {
    const senderEmail = 'craids22@gmail.com'; // <--- Make sure this matches your Gmail account for nodemailer auth

    const passStatus = isPass ? 'Passed' : 'Failed';
    const emailSubject = `Your AWSPrepZone Test Result: ${passStatus} for ${module} Module`;

    const mailOptions = {
        from: `AWSPrepZone <${senderEmail}>`,
        to: toEmail,
        subject: emailSubject,
        html: `
            <p>Dear ${username},</p>
            <p>This email is to confirm that you have completed a test on AWSPrepZone.</p>
            <p>Here are your results:</p>
            <ul>
                <li>Module Tested: <strong>${module}</strong></li>
                <li>Your Score: <strong>${score} / ${totalQuestions}</strong></li>
                <li>Result: <strong>${passStatus}</strong></li>
            </ul>
            ${isPass ? '<p>Congratulations on passing! Keep up the great work.</p>' : '<p>Keep practicing! You can do it.</p>'}
            <p>You can view your complete test history on your dashboard.</p>
            <p>Regards,<br>AWSPrepZone-Team</p>
            <p>Happy Learning! - Your Midhun Founder</p>
        `,
        text: `Dear ${username},\n\nThis email is to confirm that you have completed a test on AWSPrepZone.\n\nModule Tested: ${module}\nYour Score: ${score} / ${totalQuestions}\nResult: ${passStatus}\n\n${isPass ? 'Congratulations on passing! Keep up the great work.' : 'Keep practicing! You can do it.'}\n\nYou can find your Certificate in Dashboard\n\nRegards,\nAWSPrepZone-Team\nHappy Learning! - Your Midhun Founder`,
    };

    try {
        await gmailTransporter.sendMail(mailOptions);
        console.log(`Test completion email sent to ${toEmail} for ${module} with score ${score}.`);
        return true;
    } catch (error) {
        console.error(`Error sending test completion email to ${toEmail}:`, error);
        // Do not re-throw if email sending fails, as test result is already saved.
        // Log the error but let the main API response continue.
        return false; // Indicate failure to send email
    }
}


// --- Save Test Result Route ---
app.post('/save-test-result', authenticateUser, async (req, res) => {
    const { score, totalQuestions, isPass, module } = req.body; // Removed userName from here
    const { userId, username: loggedInUsername, email: userEmail } = req.user;

    if (score === undefined || totalQuestions === undefined || isPass === undefined || module === undefined) {
        return res.status(400).json({ message: 'Missing test result data. Make sure score, totalQuestions, isPass, and module are provided.' });
    }

    try {
        // --- NEW: Fetch CollegeName directly from Usertable using userId from token ---
        const userDetails = await dynamodb.get({
            TableName: USER_TABLE_NAME,
            Key: { UserId: userId }
        }).promise();
        const collegeNameFromUserTable = userDetails.Item ? userDetails.Item.CollegeName : 'N/A';
        // --- END NEW ---

        const newAttempt = {
            TestAttemptId : uuidv4(),
            UserId: userId,
            UserLoginUsername: loggedInUsername,
            CollegeName: collegeNameFromUserTable, // Use the CollegeName fetched from Usertable
            ModuleTested: module,
            Score: score,
            TotalQuestions: totalQuestions,
            IsPass: isPass,
            AttemptDate: new Date().toISOString()
        };

        console.log('Attempting to save new test attempt:', newAttempt);

        await dynamodb.put({
            TableName: TEST_ATTEMPTS_TABLE_NAME,
            Item: newAttempt
        }).promise();

        // Send Test Completion Email
        if (userEmail) { // Ensure userEmail is available from the token
            await sendTestCompletionEmail(userEmail, loggedInUsername, score, totalQuestions, isPass, module);
        } else {
            console.warn(`Cannot send test completion email: User email not found in token for userId: ${userId}`);
        }

        res.status(201).json({ message: 'Test result saved successfully and email sent (if email available).' });
    } catch (error) {
        console.error('Error saving test result or sending email:', error);
        res.status(500).json({ message: 'Failed to save test result: ' + error.message });
    }
});

// --- Get Test History Route ---
app.get('/get-test-history', authenticateUser, async (req, res) => {
    const { userId } = req.user;

    try {
        const params = {
            TableName: TEST_ATTEMPTS_TABLE_NAME,
            IndexName: 'UserId-AttemptDate-index',
            KeyConditionExpression: 'UserId = :userId',
            ExpressionAttributeValues: { ':userId': userId },
            ScanIndexForward: false
        };
        const result = await dynamodb.query(params).promise();
        res.status(200).json({ history: result.Items || [] });
    } catch (error) {
        console.error('Error fetching test history:', error);
        res.status(500).json({ message: 'Failed to fetch test history: ' + error.message });
    }
});

// --- Get Certificate Data Route ---
app.get('/get-certificate-data', authenticateUser, async (req, res) => {
    const { userId } = req.user;
    const { module } = req.query; // Add a query parameter to specify the module if needed for certificate generation

    try {
        // 1. Fetch user details (including CollegeName)
        const userResult = await dynamodb.get({
            TableName: USER_TABLE_NAME,
            Key: { UserId: userId }
        }).promise();

        const user = userResult?.Item;

        if (!user) {
            return res.status(404).json({ message: 'User details not found in database.' });
        }

        // 2. Fetch all passing test attempts for the user, potentially filtered by module
        const queryParams = {
            TableName: TEST_ATTEMPTS_TABLE_NAME,
            IndexName: 'UserId-AttemptDate-index',
            KeyConditionExpression: 'UserId = :userId',
            FilterExpression: 'IsPass = :isPass',
            ExpressionAttributeValues: {
                ':userId': userId,
                ':isPass': true
            },
            ScanIndexForward: false, // Sort descending by AttemptDate
        };

        if (module) {
            // If a specific module is requested for the certificate, filter by it
            queryParams.FilterExpression += ' AND ModuleTested = :moduleTested';
            queryParams.ExpressionAttributeValues[':moduleTested'] = module;
        }

        const testAttemptResult = await dynamodb.query(queryParams).promise();

        // Filter out unique modules for which a passing certificate already exists
        const modulesWithCertificates = new Set();
        let latestPassingAttemptForCertificate = null; // To store the specific attempt data for the certificate

        if (testAttemptResult?.Items && testAttemptResult.Items.length > 0) {
            for (const attempt of testAttemptResult.Items) {
                // For a "one certificate per module" rule, we care if *any* passing attempt exists for that module.
                // We'll use the *first* (most recent due to ScanIndexForward: false) passing attempt for the certificate data.
                if (!modulesWithCertificates.has(attempt.ModuleTested)) {
                    modulesWithCertificates.add(attempt.ModuleTested);
                    // If we want a certificate for a specific 'module' query param,
                    // or if it's the first passing attempt overall, store it.
                    if (module === attempt.ModuleTested || !latestPassingAttemptForCertificate) {
                        latestPassingAttemptForCertificate = attempt;
                    }
                }
            }
        }

        if (!latestPassingAttemptForCertificate) {
            return res.status(404).json({
                message: `No passing test result found for this user${module ? ` for module "${module}"` : ''}.`,
                user: {
                    username: user.Username,
                    email: user.Email
                },
                certificateAlreadyIssued: false // Indicate no certificate found/issued yet
            });
        }

        // Check if a certificate has already been "issued" for this specific module
        // This logic assumes that if a passing attempt exists for a module, a certificate has been issued for it.
        // If you need more granular control (e.g., a separate "certificates" table), that would be another modification.
        if (module && modulesWithCertificates.has(module)) {
            // A certificate for this module has already been passed/issued.
            return res.status(200).json({
                message: `A certificate for module "${module}" has already been issued for this user.`,
                studentName: user.Username,
                studentEmail: user.Email,
                studentCollege: user.CollegeName || 'N/A',
                studentScore: latestPassingAttemptForCertificate.Score,
                totalQuestions: latestPassingAttemptForCertificate.TotalQuestions,
                testDate: latestPassingAttemptForCertificate.AttemptDate,
                moduleTested: latestPassingAttemptForCertificate.ModuleTested,
                certificateAlreadyIssued: true // Flag to indicate to the frontend
            });
        } else if (!module && latestPassingAttemptForCertificate) {
            // If no specific module was requested, and we found *any* passing attempt,
            // we will provide the data for that general certificate.
            return res.status(200).json({
                studentName: user.Username,
                studentEmail: user.Email,
                studentCollege: user.CollegeName || 'N/A',
                studentScore: latestPassingAttemptForCertificate.Score,
                totalQuestions: latestPassingAttemptForCertificate.TotalQuestions,
                testDate: latestPassingAttemptForCertificate.AttemptDate,
                moduleTested: latestPassingAttemptForCertificate.ModuleTested,
                certificateAlreadyIssued: false // If we reached here, it's the first time we're providing this specific cert data.
            });
        }


        // Fallback for cases where no specific module was requested, but no overall passing attempt found.
        return res.status(404).json({
            message: 'No passing test result found for this user.',
            user: {
                username: user.Username,
                email: user.Email
            },
            certificateAlreadyIssued: false
        });

    } catch (error) {
        console.error('Error fetching certificate data:', error);
        res.status(500).json({ message: 'Failed to fetch certificate data: ' + error.message });
    }
});


// --- Route to record violations ---
app.post('/record-violation', authenticateUser, async (req, res) => {
    const { violationType, timestamp, questionIndex, module } = req.body; // Removed userName from here
    const { userId, username: loggedInUsername } = req.user;

    if (violationType === undefined || timestamp === undefined || questionIndex === undefined || module === undefined) {
        return res.status(400).json({ message: 'Missing violation data. Make sure type, timestamp, question index, and module are provided.' });
    }

    try {
        // --- NEW: Fetch CollegeName directly from Usertable for violations too ---
        const userDetails = await dynamodb.get({
            TableName: USER_TABLE_NAME,
            Key: { UserId: userId }
        }).promise();
        const collegeNameFromUserTable = userDetails.Item ? userDetails.Item.CollegeName : 'N/A';
        // --- END NEW ---

        const newViolation = {
            ViolationId: uuidv4(),
            UserId: userId,
            UserLoginUsername: loggedInUsername,
            CollegeName: collegeNameFromUserTable, // Use the CollegeName fetched from Usertable
            Module: module,
            ViolationType: violationType,
            Timestamp: timestamp, // Ensure this is stored in ISO format or similar for date range filtering
            QuestionIndex: questionIndex,
        };

        console.log('Attempting to record new violation:', newViolation);

        await dynamodb.put({
            TableName: VIOLATIONS_TABLE_NAME,
            Item: newViolation
        }).promise();

        res.status(201).json({ message: 'Violation recorded successfully.' });
    } catch (error) {
        console.error('Error recording violation:', error);
        res.status(500).json({ message: 'Failed to record violation: ' + error.message });
    }
});

// --- Save Topic Progress ---
app.post('/save-topic-progress', authenticateUser, async (req, res) => {
    const { topicNumber } = req.body;
    const { userId } = req.user;

    if (typeof topicNumber !== 'number' || topicNumber < 1 || topicNumber > NUMBER_OF_MODULES) {
        return res.status(400).json({ message: `Invalid topic number. Must be a number between 1 and ${NUMBER_OF_MODULES}.` });
    }

    const params = {
        TableName: COURSE_PROGRESS_TABLE,
        Item: {
            ProgressId: `${userId}_${topicNumber}`,
            UserId: userId,
            TopicNumber: topicNumber,
            CompletedAt: new Date().toISOString()
        }
    };

    try {
        await dynamodb.put(params).promise();
        console.log(`✅ Saved progress: Topic ${topicNumber} for user ${userId}`);
        res.status(200).json({ message: `Topic ${topicNumber} marked as completed.` });
    } catch (error) {
        console.error('❌ Error saving topic progress:', error);
        res.status(500).json({ message: 'Failed to save progress due to server error.' });
    }
});

// --- Get Completed Topics (User specific) ---
app.get('/get-topic-progress', authenticateUser, async (req, res) => {
    const { userId } = req.user;

    const params = {
        TableName: COURSE_PROGRESS_TABLE,
        IndexName: 'UserId-index', // ✅ Ensure this exists
        KeyConditionExpression: 'UserId = :userId',
        ExpressionAttributeValues: {
            ':userId': userId
        },
        ProjectionExpression: 'TopicNumber'
    };

    try {
        const result = await dynamodb.query(params).promise();
        const completedTopics = result.Items.map(item => item.TopicNumber).sort((a, b) => a - b);
        console.log(`📘 Fetched progress for user ${userId}:`, completedTopics);

        res.status(200).json({ completedTopics });
    } catch (error) {
        console.error('❌ Error fetching topic progress:', error);
        res.status(500).json({ message: 'Failed to fetch progress due to server error.' });
    }
});

// module.exports = router;

// --- Password Reset Email Sending Function ---
async function sendPasswordResetEmail(toEmail, resetToken) {
    const senderEmail = 'craids22@gmail.com';

    // Ensure baseURL is correctly configured in your ecosystem.config.js for production
    const resetLink = `${baseURL}/reset-password?token=${encodeURIComponent(resetToken)}`;

    const mailOptions = {
        from: `AWSPrepZone <${senderEmail}>`,
        to: toEmail,
        subject: "Password Reset Request for Your Account",
        html: `
            <p>You requested a password reset for your account on AWSPrepZone website.</p>
            <p>Please click the following link to reset your password:</p>
            <p><a href="${resetLink}">Reset Your Password</a></p>
            <p>This link will expire in ${PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES} minutes.</p>
            <p>If you did not request this, please ignore this email. If you seen this suspicious please report at craids22@gmail.com</p>
            <p>Regards,<br>AWSPrepZone-Team</p>
            <p>Happy Learning!- Your Midhun Founder</p>
        `,
        text: `You requested a password reset for your account. Click the following link to reset your password: ${resetLink}. This link will expire in ${PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES} minutes. If you did not request this, please ignore this email. Regards, Your Website Team`,
    };

    try {
        await gmailTransporter.sendMail(mailOptions);
        console.log(`Password reset email sent to ${toEmail} via Gmail SMTP.`);
        return true;
    } catch (error) {
        console.error(`Error sending password reset email to ${toEmail} via Gmail SMTP:`, error);
        throw new Error('Failed to send password reset email.');
    }
}


// --- Forgot Password Request Route ---
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }

    try {
        // 1. Find the user by email
        const userResult = await dynamodb.query({
            TableName: USER_TABLE_NAME,
            IndexName: 'Email-index',
            KeyConditionExpression: 'Email = :email',
            ExpressionAttributeValues: { ':email': email }
        }).promise();

        const user = userResult.Items[0];

        // Important: Always return a generic success message to prevent email enumeration
        if (!user) {
            console.warn(`Forgot password attempt for unknown email: ${email}`);
            return res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });
        }

        // 2. Generate a unique, time-limited token
        const resetToken = uuidv4();
        const now = new Date();
        const expiresAt = new Date(now.getTime() + PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES * 60 * 1000); // Token expires in X minutes

        const tokenItem = {
            Token: resetToken,
            UserId: user.UserId,
            CreatedAt: now.toISOString(),
            ExpiresAt: expiresAt.toISOString(),
            TTL: Math.floor(expiresAt.getTime() / 1000) // TTL in seconds for DynamoDB (if enabled on table)
        };

        // 3. Save the token to the PasswordResetTokens table
        await dynamodb.put({
            TableName: PASSWORD_RESET_TABLE_NAME,
            Item: tokenItem
        }).promise();

        // 4. Send email with the reset link
        await sendPasswordResetEmail(email, resetToken);

        res.status(200).json({ message: 'If an account with that email exists, a password reset link has been sent.' });

    } catch (error) {
        console.error('Error in forgot password request:', error);
        res.status(500).json({ message: 'Server error during password reset request. Please try again later.' });
    }
});

// --- Reset Password Confirmation Route ---
app.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    if (!token || !newPassword) {
        return res.status(400).json({ message: 'Token and new password are required.' });
    }

    // Basic password strength check (can be more robust)
    if (newPassword.length < 6) {
        return res.status(400).json({ message: 'New password must be at least 6 characters long.' });
    }

    try {
        // 1. Find the token in the PasswordResetTokens table
        const tokenResult = await dynamodb.get({
            TableName: PASSWORD_RESET_TABLE_NAME,
            Key: { Token: token }
        }).promise();

        const tokenRecord = tokenResult.Item;

        if (!tokenRecord) {
            console.warn(`Reset password attempt with non-existent token: ${token}`);
            return res.status(400).json({ message: 'Invalid or expired password reset token.' });
        }

        // 2. Check if the token has expired
        const expiresAt = new Date(tokenRecord.ExpiresAt);
        if (new Date() > expiresAt) {
            // Optionally delete the expired token immediately if TTL is not configured or for immediate cleanup
            await dynamodb.delete({
                TableName: PASSWORD_RESET_TABLE_NAME,
                Key: { Token: token }
            }).promise();
            console.warn(`Reset password attempt with expired token: ${token}`);
            return res.status(400).json({ message: 'Invalid or expired password reset token.' });
        }

        // 3. Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // 4. Update the user's password in the Usertable
        const updateParams = {
            TableName: USER_TABLE_NAME,
            Key: { UserId: tokenRecord.UserId }, // Use UserId from the token record
            UpdateExpression: 'SET #password = :newPassword, #updatedAt = :updatedAt',
            ExpressionAttributeNames: {
                "#password": "password", // 'password' is a reserved word in DynamoDB, so use alias
                "#updatedAt": "updatedAt"
            },
            ExpressionAttributeValues: {
                ":newPassword": hashedPassword,
                ":updatedAt": new Date().toISOString()
            },
            ReturnValues: 'UPDATED_NEW'
        };
        await dynamodb.update(updateParams).promise();

        // 5. Invalidate (delete) the used token
        await dynamodb.delete({
            TableName: PASSWORD_RESET_TABLE_NAME,
            Key: { Token: token }
        }).promise();

        res.status(200).json({ message: 'Your password has been reset successfully.' });

    } catch (error) {
        console.error('Error during password reset:', error);
        res.status(500).json({ message: 'Server error during password reset: ' + error.message });
    }
});

// --- Admin API Endpoints ---

// Helper function to get unique values (WARNING: Scans entire table, can be slow/expensive for very large tables)
async function getUniqueValues(tableName, attributeName) {
    const params = {
        TableName: tableName,
        ProjectionExpression: attributeName
    };
    const result = await dynamodb.scan(params).promise();
    const values = result.Items.map(item => item[attributeName]).filter(Boolean);
    return [...new Set(values)].sort();
}

// NEW Helper: Get UserIds by CollegeName
async function getUserIdsByCollege(collegeName) {
    if (!collegeName) return null; // If no college filter, return null to indicate no pre-filtering by users
    const params = {
        TableName: USER_TABLE_NAME,
        // Assuming you have a GSI on CollegeName if you want efficient queries.
        // Otherwise, a Scan is needed, which can be expensive.
        // For demonstration, we'll use Scan + filter if no GSI
        FilterExpression: 'CollegeName = :collegeName',
        ExpressionAttributeValues: { ':collegeName': collegeName },
        ProjectionExpression: 'UserId'
    };
    const result = await dynamodb.scan(params).promise();
    return new Set(result.Items.map(item => item.UserId)); // Return a Set for efficient lookup
}

// NEW Helper: Fetch CollegeName by UserId (for enriching data)
async function fetchCollegeNameByUserId(userId) {
    const userResult = await dynamodb.get({
        TableName: USER_TABLE_NAME,
        Key: { UserId: userId }
    }).promise();
    return userResult.Item ? userResult.Item.CollegeName : 'N/A';
}


// Admin: Get unique College Names for dropdown (requires admin authorization)
app.get('/admin/unique-colleges', authenticateUser, authorizeAdmin, async (req, res) => {
    try {
        console.log('SERVER DEBUG: /admin/unique-colleges accessed by admin:', req.user.username);
        // Corrected to fetch from USER_TABLE_NAME
        const colleges = await getUniqueValues(USER_TABLE_NAME, 'CollegeName');
        res.status(200).json({ colleges });
    } catch (error) {
        console.error('Error fetching unique colleges:', error);
        res.status(500).json({ message: 'Failed to fetch unique colleges.' });
    }
});

// Admin: Get filtered Test Attempts (requires admin authorization)
app.get('/admin/test-attempts', authenticateUser, authorizeAdmin, async (req, res) => {
    const { college, module, startDate, endDate } = req.query;
    console.log('SERVER DEBUG: /admin/test-attempts accessed by admin:', req.user.username, 'Filters:', { college, module, startDate, endDate });

    let params = {
        TableName: TEST_ATTEMPTS_TABLE_NAME,
    };

    let filterExpressions = [];
    let expressionAttributeValues = {};
    let expressionAttributeNames = {};

    if (startDate) {
        filterExpressions.push('#ad >= :startDate');
        expressionAttributeNames['#ad'] = 'AttemptDate';
        expressionAttributeValues[':startDate'] = startDate + 'T00:00:00.000Z'; // Start of the day
    }
    if (endDate) {
        filterExpressions.push('#ad <= :endDate');
        expressionAttributeNames['#ad'] = 'AttemptDate';
        expressionAttributeValues[':endDate'] = endDate + 'T23:59:59.999Z'; // End of the day
    }
    if (module) {
        filterExpressions.push('#mt = :moduleTested');
        expressionAttributeNames['#mt'] = 'ModuleTested';
        expressionAttributeValues[':moduleTested'] = module;
    }

    if (filterExpressions.length > 0) {
        params.FilterExpression = filterExpressions.join(' AND ');
        params.ExpressionAttributeValues = expressionAttributeValues;
        params.ExpressionAttributeNames = expressionAttributeNames;
    }

    try {
        const result = await dynamodb.scan(params).promise();
        let filteredAttempts = result.Items || [];

        // Step 1: Pre-fetch UserIds if college filter is applied
        const userIdsForCollege = await getUserIdsByCollege(college);

        // Step 2 & 3: Filter by college and enrich with CollegeName from Usertable
        if (userIdsForCollege) { // If college filter was specified
            const userCollegeMap = new Map(); // Cache college names to avoid redundant lookups
            const finalAttempts = [];

            for (const attempt of filteredAttempts) {
                // If the attempt's UserId is in the filtered list of UserIds
                if (userIdsForCollege.has(attempt.UserId)) {
                    // Enrich CollegeName if it's missing or if we want the definitive one from Usertable
                    if (!attempt.CollegeName || attempt.CollegeName === 'N/A') {
                        let cachedCollege = userCollegeMap.get(attempt.UserId);
                        if (!cachedCollege) {
                            cachedCollege = await fetchCollegeNameByUserId(attempt.UserId);
                            userCollegeMap.set(attempt.UserId, cachedCollege);
                        }
                        attempt.CollegeName = cachedCollege;
                    }
                    finalAttempts.push(attempt);
                }
            }
            filteredAttempts = finalAttempts;
        } else { // No college filter, just enrich any missing CollegeNames
            const userCollegeMap = new Map();
            for (const attempt of filteredAttempts) {
                if (!attempt.CollegeName || attempt.CollegeName === 'N/A') {
                    let cachedCollege = userCollegeMap.get(attempt.UserId);
                    if (!cachedCollege) {
                        cachedCollege = await fetchCollegeNameByUserId(attempt.UserId);
                        userCollegeMap.set(attempt.UserId, cachedCollege);
                    }
                    attempt.CollegeName = cachedCollege;
                }
            }
        }

        res.status(200).json({ attempts: filteredAttempts });
    } catch (error) {
        console.error('Error fetching test attempts for admin:', error);
        res.status(500).json({ message: 'Failed to fetch test attempts: ' + error.message });
    }
});


// Admin: Get filtered Violations (requires admin authorization)
app.get('/admin/violations', authenticateUser, authorizeAdmin, async (req, res) => {
    const { college, module, startDate, endDate, violationType } = req.query;
    console.log('SERVER DEBUG: /admin/violations accessed by admin:', req.user.username, 'Filters:', { college, module, startDate, endDate, violationType });

    let params = {
        TableName: VIOLATIONS_TABLE_NAME,
    };

    let filterExpressions = [];
    let expressionAttributeValues = {};
    let expressionAttributeNames = {};

    if (module) {
        filterExpressions.push('#mod = :module');
        expressionAttributeNames['#mod'] = 'Module';
        expressionAttributeValues[':module'] = module;
    }
    if (violationType) {
        filterExpressions.push('#vt = :violationType');
        expressionAttributeNames['#vt'] = 'ViolationType';
        expressionAttributeValues[':violationType'] = violationType;
    }
    if (startDate) {
        filterExpressions.push('#ts >= :startDate');
        expressionAttributeNames['#ts'] = 'Timestamp';
        expressionAttributeValues[':startDate'] = startDate + 'T00:00:00.000Z'; // Start of the day
    }
    if (endDate) {
        filterExpressions.push('#ts <= :endDate');
        expressionAttributeNames['#ts'] = 'Timestamp';
        expressionAttributeValues[':endDate'] = endDate + 'T23:59:59.999Z'; // End of the day
    }

    if (filterExpressions.length > 0) {
        params.FilterExpression = filterExpressions.join(' AND ');
        params.ExpressionAttributeValues = expressionAttributeValues;
        params.ExpressionAttributeNames = expressionAttributeNames;
    }

    try {
        const result = await dynamodb.scan(params).promise();
        let filteredViolations = result.Items || [];

        // Step 1: Pre-fetch UserIds if college filter is applied
        const userIdsForCollege = await getUserIdsByCollege(college);

        // Step 2 & 3: Filter by college and enrich with CollegeName from Usertable
        if (userIdsForCollege) { // If college filter was specified
            const userCollegeMap = new Map(); // Cache college names to avoid redundant lookups
            const finalViolations = [];

            for (const violation of filteredViolations) {
                // If the violation's UserId is in the filtered list of UserIds
                if (userIdsForCollege.has(violation.UserId)) {
                    // Enrich CollegeName if it's missing or if we want the definitive one from Usertable
                    if (!violation.CollegeName || violation.CollegeName === 'N/A') {
                        let cachedCollege = userCollegeMap.get(violation.UserId);
                        if (!cachedCollege) {
                            cachedCollege = await fetchCollegeNameByUserId(violation.UserId);
                            userCollegeMap.set(violation.UserId, cachedCollege);
                        }
                        violation.CollegeName = cachedCollege;
                    }
                    finalViolations.push(violation);
                }
            }
            filteredViolations = finalViolations;
        } else { // No college filter, just enrich any missing CollegeNames
            const userCollegeMap = new Map();
            for (const violation of filteredViolations) {
                if (!violation.CollegeName || violation.CollegeName === 'N/A') {
                    let cachedCollege = userCollegeMap.get(violation.UserId);
                    if (!cachedCollege) {
                        cachedCollege = await fetchCollegeNameByUserId(violation.UserId);
                        userCollegeMap.set(violation.UserId, cachedCollege);
                    }
                    violation.CollegeName = cachedCollege;
                }
            }
        }

        res.status(200).json({ violations: filteredViolations });
    } catch (error) {
        console.error('Error fetching violations for admin:', error);
        res.status(500).json({ message: 'Failed to fetch violations: ' + error.message });
    }
});


// Admin: Get unique Violation Types for dropdown (requires admin authorization)
app.get('/admin/unique-violation-types', authenticateUser, authorizeAdmin, async (req, res) => {
    try {
        console.log('SERVER DEBUG: /admin/unique-violation-types accessed by admin:', req.user.username);
        const violationTypes = await getUniqueValues(VIOLATIONS_TABLE_NAME, 'ViolationType');
        res.status(200).json({ violationTypes });
    } catch (error) {
        console.error('Error fetching unique violation types:', error);
        res.status(500).json({ message: 'Failed to fetch unique violation types.' });
    }
});

// NEW ADMIN ENDPOINT: Get Learning Progress for Admins (filtered by college)
app.get('/admin/learning-progress', authenticateUser, authorizeAdmin, async (req, res) => {
    const { college } = req.query; // Only college filter for now
    console.log('SERVER DEBUG: /admin/learning-progress accessed by admin:', req.user.username, 'Filter:', { college });

    let params = {
        TableName: COURSE_PROGRESS_TABLE,
    };

    try {
        const result = await dynamodb.scan(params).promise();
        let learningProgress = result.Items || [];

        // Step 1: Pre-fetch UserIds if college filter is applied
        const userIdsForCollege = await getUserIdsByCollege(college);

        // Step 2 & 3: Filter by college and enrich with CollegeName from Usertable
        if (userIdsForCollege) { // If college filter was specified
            const userCollegeMap = new Map(); // Cache college names to avoid redundant lookups
            const finalProgress = [];

            for (const progress of learningProgress) {
                // If the progress's UserId is in the filtered list of UserIds
                if (userIdsForCollege.has(progress.UserId)) {
                    let cachedCollege = userCollegeMap.get(progress.UserId);
                    if (!cachedCollege) {
                        cachedCollege = await fetchCollegeNameByUserId(progress.UserId);
                        userCollegeMap.set(progress.UserId, cachedCollege);
                    }
                    progress.CollegeName = cachedCollege; // Add CollegeName to the progress item
                    finalProgress.push(progress);
                }
            }
            learningProgress = finalProgress;
        } else { // No college filter, just enrich each item with CollegeName
            const userCollegeMap = new Map();
            for (const progress of learningProgress) {
                let cachedCollege = userCollegeMap.get(progress.UserId);
                if (!cachedCollege) {
                    cachedCollege = await fetchCollegeNameByUserId(progress.UserId);
                    userCollegeMap.set(progress.UserId, cachedCollege);
                }
                progress.CollegeName = cachedCollege; // Add CollegeName to the progress item
            }
        }

        res.status(200).json({ learningProgress });
    } catch (error) {
        console.error('Error fetching learning progress for admin:', error);
        res.status(500).json({ message: 'Failed to fetch learning progress: ' + error.message });
    }
});
// backend.js

// ... existing imports and setup ...

// New endpoint to get all passing certificates for the logged-in user
// --- NEW Endpoint: Get All Passing Certificates for Frontend List ---
app.get('/get-all-passing-certificates', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.userId;

        const params = {
            TableName: TEST_ATTEMPTS_TABLE_NAME,
            IndexName: 'UserId-AttemptDate-index', // Ensure this GSI exists and is properly configured
            KeyConditionExpression: 'UserId = :userId',
            FilterExpression: 'IsPass = :isPass',
            ExpressionAttributeValues: {
                ':userId': userId,
                ':isPass': true
            },
            ScanIndexForward: false // Sort by AttemptDate descending to easily get the latest
        };

        let allPassingAttempts = [];
        let data;
        do {
            data = await dynamodb.query(params).promise();
            allPassingAttempts = allPassingAttempts.concat(data.Items);
            params.ExclusiveStartKey = data.LastEvaluatedKey;
        } while (typeof data.LastEvaluatedKey !== 'undefined');

        // Group by ModuleTested and keep only the latest attempt for each module
        const latestAttemptsByModule = new Map(); // Map to store the latest attempt for each module
        for (const attempt of allPassingAttempts) {
            const moduleName = attempt.ModuleTested;
            // If the module is not yet in the map, or if the current attempt is newer than the one in the map
            if (!latestAttemptsByModule.has(moduleName) || new Date(attempt.AttemptDate) > new Date(latestAttemptsByModule.get(moduleName).AttemptDate)) {
                latestAttemptsByModule.set(moduleName, attempt);
            }
        }

        // Convert map values back to an array
        const uniquePassingCertificates = Array.from(latestAttemptsByModule.values());

        // Format data for the frontend
        const formattedCertificates = uniquePassingCertificates.map(attempt => ({
            testAttemptId: attempt.TestAttemptId, // Unique ID for each attempt
            studentName: attempt.UserLoginUsername, // Use UserLoginUsername from TestAttempts
            studentScore: attempt.Score,
            totalQuestions: attempt.TotalQuestions,
            moduleTested: attempt.ModuleTested, // 'ModuleTested' from TestAttempts
            testDate: attempt.AttemptDate
        }));

        res.status(200).json({ certificates: formattedCertificates });

    } catch (error) {
        console.error('Error fetching all passing certificates:', error);
        res.status(500).json({ message: 'Failed to fetch all passing certificates: ' + error.message });
    }
});
async function fetchTestSummary() {
  const jwtToken = localStorage.getItem('jwtToken');
  console.log('DEBUG: Token found in localStorage:', jwtToken ? 'YES' : 'NO'); // Add this line
  debugger; // PAUSE 1: Check jwtToken value here

  if (!jwtToken) {
      console.warn('JWT token not found. Cannot fetch test summary.');
      // ... rest of your code
      return;
  }
  try {
      debugger; // PAUSE 2: Check if execution reaches here, means token was present
      const res = await fetch(`${API_BASE_URL}/get-test-history`, {
          headers: { 'Authorization': `Bearer ${jwtToken}` }
      });
      // ... rest
  } catch (err) {
      console.error('Failed to fetch test summary:', err);
  }
}


app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access the application at ${baseURL}`);
});
