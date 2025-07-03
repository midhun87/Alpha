// backend.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const AWS = require('aws-sdk');
const nodemailer = require('nodemailer'); // Added for email functionality
require('dotenv').config(); // Add this line to load environment variables from .env file
const baseURL = process.env.BASE_URL || 'http://localhost:5000'; 

AWS.config.update({
    region: 'ap-south-1', // IMPORTANT: This region must match where your DynamoDB tables are located.
    accessKeyId: process.env.AWS_ACCESS_KEY_ID || 'AKIAVEP3EDM5K3LA5J47', // Use env var or provided key
    secretAccessKey: process.env.AWS_ACCESS_KEY_ID || 'YfIszgolrWKUglxC6Q85HSb3V0qhDsa00yv6jcIP' // Use env var or provided key
});

const dynamodb = new AWS.DynamoDB.DocumentClient();

// --- Nodemailer Transporter for GMAIL SMTP (using your App Password) ---
// IMPORTANT: Replace 'yourgmailaccount@gmail.com' with the actual Gmail address
// for which you generated the App Password.
const gmailTransporter = nodemailer.createTransport({
    service: 'gmail', // This tells Nodemailer to use Gmail's well-known settings
    auth: {
        user: 'craids22@gmail.com', // <--- REPLACE THIS with YOUR GMAIL ADDRESS
        pass: 'opok nwqf kukx aihh' // <--- YOUR GENERATED APP PASSWORD
    }
});

// --- Constants ---
const SECRET_KEY = 'jwt_secret_key_54742384238423_ahfgrdtTFHHYJNMP[]yigfgfjdfjd=-+&+pqiel;,,dkvntegdv/cv,mbkzmbzbhsbha#&$^&(#_enD';
const PORT = 5000;
const USER_TABLE_NAME = 'Usertable';
const TEST_ATTEMPTS_TABLE_NAME = 'TestAttempts';
const COURSE_PROGRESS_TABLE = 'CourseProgress';
const VIOLATIONS_TABLE_NAME = 'ViolationsTable';
const PASSWORD_RESET_TABLE_NAME = 'PasswordResetTokens'; // NEW: Table for password reset tokens
const PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES = 60; // NEW: Token valid for 60 minutes

const ALL_QUESTIONS_DATA = require('./questions.json');

const NUMBER_OF_QUESTIONS_PER_TEST = 25;
const NUMBER_OF_MODULES = 25;

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
        const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS512'] });
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
    console.log('SERVER DEBUG: authorizeAdmin called. User role from token:', req.user ? req.user.role : 'N/A (req.user missing)');
    if (req.user && req.user.role === 'admin') {
        next(); // User is an admin, proceed
    } else {
        console.warn(`SERVER DEBUG: Unauthorized access attempt to admin page by user: ${req.user ? req.user.username : 'Unknown'} with role: ${req.user ? req.user.role : 'N/A'}`);
        res.status(403).json({ message: 'Forbidden: Admin access required.' });
    }
}


// --- Signup Route ---
app.post('/signup', async (req, res) => {
    const { email, password, username, mobile } = req.body;

    if (!email || !password || !username || !mobile) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    try {
        if (await checkIfAttributeExists(USER_TABLE_NAME, 'Username-index', 'Username', username.toLowerCase())) {
            return res.status(400).json({ message: 'Username already in use.' });
        }
        if (await checkIfAttributeExists(USER_TABLE_NAME, 'Email-index', 'Email', email)) {
            return res.status(400).json({ message: 'Email already in use.' });
        }
        if (await checkIfAttributeExists(USER_TABLE_NAME, 'Mobile-index', 'Mobile', mobile)) {
            return res.status(400).json({ message: 'Mobile number already in use.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            UserId: uuidv4(),
            Email: email,
            Mobile: mobile,
            password: hashedPassword,
            Username: username.toLowerCase(),
            role: 'user', // Default role for new signups
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        await dynamodb.put({
            TableName: USER_TABLE_NAME,
            Item: newUser
        }).promise();

        res.status(201).json({ message: 'User created successfully. Please log in.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during signup: ' + error.message });
    }
});

// --- Login Route ---
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    try {
        const result = await dynamodb.query({
            TableName: USER_TABLE_NAME,
            IndexName: 'Email-index',
            KeyConditionExpression: 'Email = :email',
            ExpressionAttributeValues: { ':email': email }
        }).promise();

        const user = result.Items[0];
        if (!user) {
            console.warn('SERVER DEBUG: Login failed - User not found for email:', email);
            return res.status(400).json({ message: 'Invalid credentials: User not found.' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            console.warn('SERVER DEBUG: Login failed - Password mismatch for user:', user.Username);
            return res.status(400).json({ message: 'Invalid credentials: Password mismatch.' });
        }

        // Include the user's role in the JWT payload
        const token = jwt.sign(
            {
                userId: user.UserId,
                username: user.Username,
                email: user.Email, // Include email in token payload for convenience
                role: user.role || 'user' // Default to 'user' if role not explicitly set
            },
            SECRET_KEY,
            { expiresIn: '1h', algorithm: 'HS512' }
        );
        console.log('SERVER DEBUG: Login successful. Generated JWT token (first 20 chars):', token.substring(0, 20) + '...');
        console.log('SERVER DEBUG: User role included in token:', user.role || 'user');

        res.status(200).json({
            token,
            username: user.Username,
            userId: user.UserId,
            email: user.Email,
            mobile: user.Mobile,
            role: user.role || 'user' // Also send role directly to frontend if needed
        });
    } catch (error) {
        console.error('SERVER ERROR: Login error:', error);
        res.status(500).json({ message: 'Server error during login: ' + error.message });
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
        text: `Dear ${username},\n\nThis email is to confirm that you have completed a test on AWSPrepZone.\n\nModule Tested: ${module}\nYour Score: ${score} / ${totalQuestions}\nResult: ${passStatus}\n\n${isPass ? 'Congratulations on passing! Keep up the great work.' : 'Keep practicing! You can do it.'}\n\nYou can view your complete test history on your dashboard.\n\nRegards,\nAWSPrepZone-Team\nHappy Learning! - Your Midhun Founder`,
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
    const { score, totalQuestions, isPass, userName, module } = req.body;
    // Extract userId, username, and email from the authenticated user (email is now included in token)
    const { userId, username: loggedInUsername, email: userEmail } = req.user; 

    if (score === undefined || totalQuestions === undefined || isPass === undefined || userName === undefined || module === undefined) {
        return res.status(400).json({ message: 'Missing test result data. Make sure score, totalQuestions, isPass, college name, and module are provided.' });
    }

    try {
        const newAttempt = {
            TestAttemptId : uuidv4(),
            UserId: userId,
            UserLoginUsername: loggedInUsername,
            CollegeName: userName,
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

        // --- NEW: Send Test Completion Email ---
        // Call the new function here, after successfully saving the test result
        if (userEmail) { // Ensure userEmail is available from the token
            await sendTestCompletionEmail(userEmail, loggedInUsername, score, totalQuestions, isPass, module);
        } else {
            console.warn(`Cannot send test completion email: User email not found in token for userId: ${userId}`);
        }
        // --- END NEW ---

        res.status(201).json({ message: 'Test result saved successfully and email sent (if email available).' }); // Updated message
    } catch (error) {
        console.error('Error saving test result or sending email:', error); // Updated error log
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

    try {
        const userParams = {
            TableName: USER_TABLE_NAME,
            Key: {
                UserId: userId
            }
        };
        const userResult = await dynamodb.get(userParams).promise();
        const user = userResult.Item;

        if (!user) {
            return res.status(404).json({ message: 'User details not found in database.' });
        }

        const testAttemptParams = {
            TableName: TEST_ATTEMPTS_TABLE_NAME,
            IndexName: 'UserId-AttemptDate-index', // Ensure this index exists in DynamoDB
            KeyConditionExpression: 'UserId = :userId',
            FilterExpression: 'IsPass = :isPass',
            ExpressionAttributeValues: {
                ':userId': userId,
                ':isPass': true
            },
            ScanIndexForward: false, // Get the most recent passing attempt
            Limit: 1
        };

        const testAttemptResult = await dynamodb.query(testAttemptParams).promise();
        const latestPassingAttempt = testAttemptResult.Items && testAttemptResult.Items[0];

        if (!latestPassingAttempt) {
            return res.status(404).json({ message: 'No passing test result found for this user.', user: { username: user.Username, email: user.Email } });
        }

        res.status(200).json({
            studentName: user.Username,
            studentEmail: user.Email,
            studentCollege: latestPassingAttempt.CollegeName,
            studentScore: latestPassingAttempt.Score,
            totalQuestions: latestPassingAttempt.TotalQuestions,
            testDate: latestPassingAttempt.AttemptDate,
            moduleTested: latestPassingAttempt.ModuleTested
        });

    } catch (error) {
        console.error('Error fetching certificate data:', error);
        res.status(500).json({ message: 'Failed to fetch certificate data: ' + error.message });
    }
});
// --- Route to record violations ---
app.post('/record-violation', authenticateUser, async (req, res) => {
    const { violationType, timestamp, questionIndex, userName, module } = req.body;
    const { userId, username: loggedInUsername } = req.user;

    if (violationType === undefined || timestamp === undefined || questionIndex === undefined || userName === undefined || module === undefined) {
        return res.status(400).json({ message: 'Missing violation data. Make sure type, timestamp, question index, college name, and module are provided.' });
    }

    try {
        const newViolation = {
            ViolationId: uuidv4(),
            UserId: userId,
            UserLoginUsername: loggedInUsername,
            CollegeName: userName,
            Module: module,
            ViolationType: violationType,
            Timestamp: timestamp,
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
        res.status(200).json({ message: `Topic ${topicNumber} marked as completed for user ${userId}.` });
    } catch (error) {
        console.error('Error saving topic progress:', error);
        res.status(500).json({ message: 'Failed to save progress due to server error.' });
    }
});

// --- Get Completed Topics ---
app.get('/get-topic-progress', authenticateUser, async (req, res) => {
    const { userId } = req.user;

    const params = {
        TableName: COURSE_PROGRESS_TABLE,
        IndexName: 'UserId-index', // Ensure this index exists in DynamoDB
        KeyConditionExpression: 'UserId = :userId',
        ExpressionAttributeValues: {
            ':userId': userId
        },
        ProjectionExpression: 'TopicNumber'
    };

    try {
        const result = await dynamodb.query(params).promise();
        const completedTopics = result.Items.map(item => item.TopicNumber).sort((a, b) => a - b);
        res.status(200).json({ completedTopics });
    } catch (error) {
        console.error('Error fetching topic progress:', error);
        res.status(500).json({ message: 'Failed to fetch progress due to server error.' });
    }
});


// --- Password Reset Email Sending Function ---
async function sendPasswordResetEmail(toEmail, resetToken) {
    const senderEmail = 'craids22@gmail.com'; 

    // Ensure baseURL is correctly configured in your ecosystem.config.js for production
const resetLink = `http://15.207.55.68:5000/reset-password?token=${encodeURIComponent(resetToken)}`;


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

// Admin: Get unique College Names for dropdown (requires admin authorization)
app.get('/admin/unique-colleges', authenticateUser, authorizeAdmin, async (req, res) => {
    try {
        console.log('SERVER DEBUG: /admin/unique-colleges accessed by admin:', req.user.username);
        const colleges = await getUniqueValues(TEST_ATTEMPTS_TABLE_NAME, 'CollegeName');
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

    if (college) {
        filterExpressions.push('#cn = :collegeName');
        expressionAttributeNames['#cn'] = 'CollegeName';
        expressionAttributeValues[':collegeName'] = college;
    }
    if (module) {
        filterExpressions.push('#mt = :moduleTested');
        expressionAttributeNames['#mt'] = 'ModuleTested';
        expressionAttributeValues[':moduleTested'] = module;
    }
    if (startDate) {
        filterExpressions.push('#ad >= :startDate');
        expressionAttributeNames['#ad'] = 'AttemptDate';
        expressionAttributeValues[':startDate'] = startDate + 'T00:00:00.000Z';
    }
    if (endDate) {
        filterExpressions.push('#ad <= :endDate');
        expressionAttributeNames['#ad'] = 'AttemptDate';
        expressionAttributeValues[':endDate'] = endDate + 'T23:59:59.999Z';
    }

    if (filterExpressions.length > 0) {
        params.FilterExpression = filterExpressions.join(' AND ');
        params.ExpressionAttributeValues = expressionAttributeValues;
        params.ExpressionAttributeNames = expressionAttributeNames;
    }

    try {
        const result = await dynamodb.scan(params).promise();
        const sortedAttempts = result.Items.sort((a, b) => new Date(b.AttemptDate) - new Date(a.AttemptDate));
        res.status(200).json({ attempts: sortedAttempts });
    } catch (error) {
        console.error('Error fetching test attempts for admin:', error);
        res.status(500).json({ message: 'Failed to fetch test attempts: ' + error.message });
    }
});

// --- Server Start ---
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access frontend at http://localhost:${PORT}`);
});
