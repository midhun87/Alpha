// backend.js
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const AWS = require('aws-sdk');
require('dotenv').config(); // Add this line to load environment variables from .env file


AWS.config.update({
    region: 'ap-south-1', // IMPORTANT: This region must match where your DynamoDB tables are located.
    accessKeyId: 'AKIAVEP3EDM5K3LA5J47', // Replace with your actual Access Key ID (securely!)
    secretAccessKey: 'YfIszgolrWKUglxC6Q85HSb3V0qhDsa00yv6jcIP' // Replace with your actual Secret Access Key (securely!)
});

const dynamodb = new AWS.DynamoDB.DocumentClient();

// --- Constants ---
const SECRET_KEY = 'jwt_secret_key_54742384238423_ahfgrdtTFHHYJNMP[]yigfgfjdfjd=-+&+pqiel;,,dkvntegdv/cv,mbkzmbzbhsbha#&$^&(#_enD';
const PORT = 5000;
const USER_TABLE_NAME = 'Usertable'; // Your existing user table
const TEST_ATTEMPTS_TABLE_NAME = 'TestAttempts'; // New table for test results
const COURSE_PROGRESS_TABLE = 'CourseProgress'; // New DynamoDB table
const VIOLATIONS_TABLE_NAME = 'ViolationsTable';

const ALL_QUESTIONS_DATA = require('./questions.json'); // Ensure this file exists and is correctly formatted

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
// Admin page is now served directly. Frontend JS will handle auth/redirect.
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'Admin.html')));
app.use('/pdfs', express.static(path.join(__dirname, 'PPts')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'welcome.html')));

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


// --- Helper Function for DynamoDB Checks (used in signup) ---
async function checkIfAttributeExists(tableName, indexName, attributeName, value) {
    const params = {
        TableName: tableName,
        IndexName: indexName, // Ensure this index exists in DynamoDB
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
    // console.log('SERVER DEBUG: authenticateUser called. Authorization header:', authHeader); // Log full header
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        console.warn('SERVER DEBUG: Auth header missing or malformed.');
        return res.status(401).json({ message: 'Authorization token not provided or malformed.' });
    }
    const token = authHeader.replace('Bearer ', '');
    // console.log('SERVER DEBUG: Token extracted (first 20 chars):', token.substring(0, 20) + '...'); // Log partial token
    try {
        const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ['HS512'] });
        // console.log('SERVER DEBUG: Token decoded successfully. User ID:', decoded.userId, 'Role:', decoded.role); // Log decoded info
        req.user = decoded;
        next();
    } catch (error) {
        console.error('SERVER ERROR: JWT Verification FAILED:', error.message, 'Name:', error.name); // Log detailed error
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
    // console.log('SERVER DEBUG: authorizeAdmin called. User role from token:', req.user ? req.user.role : 'N/A (req.user missing)'); // Log role check
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
        // These index names must match your DynamoDB secondary indexes
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
            password: hashedPassword, // Store hashed password
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
            IndexName: 'Email-index', // Ensure this index exists in DynamoDB
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
                email: user.Email,
                role: user.role || 'user' // Default to 'user' if role not explicitly set
            },
            SECRET_KEY,
            { expiresIn: '1h', algorithm: 'HS512' }
        );
        // console.log('SERVER DEBUG: Login successful. Generated JWT token (first 20 chars):', token.substring(0, 20) + '...');
        // console.log('SERVER DEBUG: User role included in token:', user.role || 'user');

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

        // --- MODIFIED SECTION: Send the full question objects including correctAnswerIndex ---
        // The frontend Test.html needs correctAnswerIndex for scoring and review.
        res.status(200).json({ questions: finalQuestions, moduleTested: moduleName });
        // --- END MODIFIED SECTION ---

    } catch (error) {
        console.error('Error selecting questions:', error);
        res.status(500).json({ message: 'Failed to retrieve test questions.' });
    }
});

// --- Save Test Result Route ---
app.post('/save-test-result', authenticateUser, async (req, res) => {
    const { score, totalQuestions, isPass, userName, module } = req.body;
    const { userId, username: loggedInUsername } = req.user;

    if (score === undefined || totalQuestions === undefined || isPass === undefined || userName === undefined || module === undefined) {
        return res.status(400).json({ message: 'Missing test result data. Make sure score, totalQuestions, isPass, college name, and module are provided.' });
    }

    try {
        const newAttempt = {
            TestAttemptId : uuidv4(),
            UserId: userId,
            UserLoginUsername: loggedInUsername,
            CollegeName: userName, // Assuming 'userName' from frontend is college name
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

        res.status(201).json({ message: 'Test result saved successfully.' });
    } catch (error) {
        console.error('Error saving test result:', error);
        res.status(500).json({ message: 'Failed to save test result: ' + error.message });
    }
});

// --- Get Test History Route ---
app.get('/get-test-history', authenticateUser, async (req, res) => {
    const { userId } = req.user;

    try {
        const params = {
            TableName: TEST_ATTEMPTS_TABLE_NAME,
            IndexName: 'UserId-AttemptDate-index', // Ensure this index exists in DynamoDB
            KeyConditionExpression: 'UserId = :userId',
            ExpressionAttributeValues: { ':userId': userId },
            ScanIndexForward: false // Latest attempts first
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
        // Using scan for filtering. For large datasets, consider designing DynamoDB queries with appropriate indexes
        // if these filters are frequently used for large data.
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
