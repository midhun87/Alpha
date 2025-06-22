// questionsData.js

const INFRASTRUCTURE_QUESTIONS_DATA = [
    {
        id: "infra-001",
        question: "Which AWS service helps you deploy and scale your web applications and services written in various programming languages, without managing the underlying infrastructure?",
        options: [
            "Amazon EC2",
            "AWS Lambda",
            "AWS Elastic Beanstalk",
            "Amazon S3"
        ],
        correctAnswerIndex: 2,
        category: "Infrastructure"
    },
    {
        id: "infra-002",
        question: "What is the global infrastructure component that represents a distinct geographic area where AWS services are hosted?",
        options: [
            "Availability Zone",
            "Region",
            "Edge Location",
            "Local Zone"
        ],
        correctAnswerIndex: 1,
        category: "Infrastructure"
    },
    {
        id: "infra-003",
        question: "Which AWS service provides highly available, scalable, and secure DNS web service?",
        options: [
            "Amazon CloudFront",
            "Amazon Route 53",
            "AWS Global Accelerator",
            "AWS Direct Connect"
        ],
        correctAnswerIndex: 1,
        category: "Infrastructure"
    },
    // ... Add 72 more Infrastructure questions here (total 75)
    // Example: { id: "infra-075", question: "...", options: [], correctAnswerIndex: X, category: "Infrastructure" }
];

const CLOUD_COMPUTING_QUESTIONS_DATA = [
    {
        id: "cloud-001",
        question: "What are the three common cloud computing service models?",
        options: [
            "IaaS, PaaS, SaaS",
            "Public, Private, Hybrid",
            "EC2, S3, Lambda",
            "On-Premise, Cloud-Native, Serverless"
        ],
        correctAnswerIndex: 0,
        category: "Cloud Computing"
    },
    {
        id: "cloud-002",
        question: "Which cloud computing deployment model allows organizations to maintain some resources on-premises while leveraging cloud services for others?",
        options: [
            "Public Cloud",
            "Private Cloud",
            "Hybrid Cloud",
            "Community Cloud"
        ],
        correctAnswerIndex: 2,
        category: "Cloud Computing"
    },
    {
        id: "cloud-003",
        question: "What is a benefit of cloud computing where you only pay for the compute, storage, and other resources you actually use?",
        options: [
            "Global Reach",
            "High Availability",
            "Pay-as-you-go pricing",
            "Economies of scale"
        ],
        correctAnswerIndex: 2,
        category: "Cloud Computing"
    },
    // ... Add 72 more Cloud Computing questions here (total 75)
];

const INTERACTION_QUESTIONS_DATA = [
    {
        id: "interact-001",
        question: "Which AWS service is primarily used for sending push notifications to mobile devices, email, and SMS?",
        options: [
            "Amazon SQS",
            "Amazon SNS",
            "AWS Step Functions",
            "Amazon EventBridge"
        ],
        correctAnswerIndex: 1,
        category: "Interaction"
    },
    // ... Add 74 more Interaction questions here (total 75)
];

const STORAGE_QUESTIONS_DATA = [
    {
        id: "storage-001",
        question: "Which AWS storage service is best suited for highly durable, scalable, object storage for static website hosting?",
        options: [
            "Amazon EBS",
            "Amazon EFS",
            "Amazon S3",
            "AWS Storage Gateway"
        ],
        correctAnswerIndex: 2,
        category: "Storage"
    },
    // ... Add 74 more Storage questions here (total 75)
];

const COMPUTE_SERVICES_QUESTIONS_DATA = [
    {
        id: "compute-001",
        question: "Which AWS compute service allows you to run code without provisioning or managing servers?",
        options: [
            "Amazon EC2",
            "AWS Lambda",
            "Amazon ECS",
            "AWS Fargate"
        ],
        correctAnswerIndex: 1,
        category: "Compute Services"
    },
    // ... Add 74 more Compute Services questions here (total 75)
];

const PRICING_QUESTIONS_DATA = [
    {
        id: "pricing-001",
        question: "Which pricing model allows you to reserve EC2 instances for a one-year or three-year term at a significant discount?",
        options: [
            "On-Demand Instances",
            "Spot Instances",
            "Reserved Instances",
            "Dedicated Hosts"
        ],
        correctAnswerIndex: 2,
        category: "Pricing"
    },
    // ... Add 74 more Pricing questions here (total 75)
];

const AWS_NETWORKING_QUESTIONS_DATA = [
    {
        id: "network-001",
        question: "What is a virtual network dedicated to your AWS account, isolated from other virtual networks in the AWS Cloud?",
        options: [
            "Virtual Private Cloud (VPC)",
            "Direct Connect",
            "Route 53",
            "CloudFront"
        ],
        correctAnswerIndex: 0,
        category: "AWS Networking"
    },
    // ... Add 74 more AWS Networking questions here (total 75)
];

const AWS_DATABASES_QUESTIONS_DATA = [
    {
        id: "db-001",
        question: "Which AWS service is a fully managed NoSQL database service?",
        options: [
            "Amazon RDS",
            "Amazon Aurora",
            "Amazon DynamoDB",
            "Amazon Redshift"
        ],
        correctAnswerIndex: 2,
        category: "AWS Databases"
    },
    // ... Add 74 more AWS Databases questions here (total 75)
];

const MONITORING_QUESTIONS_DATA = [
    {
        id: "monitor-001",
        question: "Which AWS service collects monitoring and operational data in the form of logs, metrics, and events?",
        options: [
            "AWS CloudTrail",
            "Amazon GuardDuty",
            "Amazon CloudWatch",
            "AWS Config"
        ],
        correctAnswerIndex: 2,
        category: "Monitoring"
    },
    // ... Add 74 more Monitoring questions here (total 75)
];

const SECURITY_QUESTIONS_DATA = [
    {
        id: "security-001",
        question: "Which AWS service is used to control who is authenticated and authorized to use AWS resources?",
        options: [
            "AWS KMS",
            "AWS WAF",
            "AWS IAM",
            "Amazon Cognito"
        ],
        correctAnswerIndex: 2,
        category: "Security"
    },
    // ... Add 74 more Security questions here (total 75)
];

const SHARED_MODEL_QUESTIONS_DATA = [
    {
        id: "shared-001",
        question: "Under the AWS Shared Responsibility Model, who is responsible for security *in* the cloud?",
        options: [
            "AWS",
            "The customer",
            "A third-party auditor",
            "Both AWS and the customer"
        ],
        correctAnswerIndex: 1,
        category: "Shared_model"
    },
    // ... Add 74 more Shared Model questions here (total 75)
];

const CAF_QUESTIONS_DATA = [
    {
        id: "caf-001",
        question: "Which perspective of the AWS Cloud Adoption Framework (CAF) focuses on aligning IT strategy with business strategy?",
        options: [
            "Business",
            "People",
            "Governance",
            "Platform"
        ],
        correctAnswerIndex: 0,
        category: "CAF"
    },
    // ... Add 74 more CAF questions here (total 75)
];

const SERVICES_QUESTIONS_DATA = [
    {
        id: "services-001",
        question: "Which AWS service is used for serverless orchestration of workflows?",
        options: [
            "AWS Lambda",
            "AWS Step Functions",
            "Amazon SQS",
            "Amazon SNS"
        ],
        correctAnswerIndex: 1,
        category: "Services"
    },
    // ... Add 74 more Services questions here (total 75)
];

// ALL Questions Data (150 questions - combine distinct sets or have a separate 150)
// For demonstration, combining some categories to meet 150, but you should use your specific 150 questions.
const ALL_QUESTIONS_DATA = [
    ...generateDummyQuestions(50, "ALL-General-Part1"),
    ...generateDummyQuestions(50, "ALL-General-Part2"),
    ...generateDummyQuestions(50, "ALL-General-Part3")
    // Replace these with your actual 150 questions.
    // Example: { id: "all-150", question: "...", options: [], correctAnswerIndex: X, category: "General AWS" }
];

// Helper to generate dummy questions for ALL category, if you don't have 150 unique
function generateDummyQuestions(count, prefix) {
    const questions = [];
    for (let i = 1; i <= count; i++) {
        questions.push({
            id: `${prefix}-q${i}`,
            question: `[${prefix}] This is a general AWS question number ${i}.`,
            options: [`Option A ${i}`, `Option B ${i}`, `Option C ${i}`, `Option D ${i}`],
            correctAnswerIndex: 0,
            category: prefix // Can be a broader category like "General AWS"
        });
    }
    return questions;
}


module.exports = {
    INFRASTRUCTURE_QUESTIONS_DATA,
    CLOUD_COMPUTING_QUESTIONS_DATA,
    INTERACTION_QUESTIONS_DATA,
    STORAGE_QUESTIONS_DATA,
    COMPUTE_SERVICES_QUESTIONS_DATA,
    PRICING_QUESTIONS_DATA,
    AWS_NETWORKING_QUESTIONS_DATA,
    AWS_DATABASES_QUESTIONS_DATA,
    MONITORING_QUESTIONS_DATA,
    SECURITY_QUESTIONS_DATA,
    SHARED_MODEL_QUESTIONS_DATA,
    CAF_QUESTIONS_DATA,
    SERVICES_QUESTIONS_DATA,
    ALL_QUESTIONS_DATA
};