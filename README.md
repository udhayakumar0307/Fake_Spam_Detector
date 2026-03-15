# Fake Spam Detector

## Overview
Fake Spam Detector is a cloud-based web application designed to identify and validate suspicious phone numbers and email addresses. The system helps users detect potential spam or fraudulent contact details by integrating reliable third-party verification APIs and secure AWS cloud services.

This project provides a simple interface where users can submit an email address or phone number and receive validation results in real time.

## Problem Statement
Spam emails and fraudulent phone numbers are commonly used in phishing attacks, scams, and cyber fraud. Many users unknowingly interact with these malicious contacts, leading to data theft, financial loss, and security risks.

There is a need for a system that can quickly verify whether a phone number or email address is legitimate before users trust or interact with it.

## Solution
The Fake Spam Detector validates phone numbers and email addresses using trusted external APIs and stores verification results securely in the cloud for monitoring and analysis.

The system performs:
- Phone number validation using **NumVerify API**
- Email validation using **AbstractAPI Email Validation**
- Secure storage of detection results using **AWS DynamoDB**
- Cloud-based deployment for fast and scalable access

## Features
- Real-time email validation
- Phone number verification
- Cloud-based architecture
- Secure data storage using AWS DynamoDB
- Fast global access through AWS CloudFront
- Simple and user-friendly web interface

## Technologies Used
- **Frontend:** HTML, CSS, JavaScript  
- **Backend APIs:** NumVerify API, AbstractAPI Email Validation  
- **Cloud Services:** AWS DynamoDB, AWS CloudFront  
- **Hosting:** AWS Cloud Infrastructure  

## Live Web Application
Access the deployed project here:

🔗 https://d7se5079ygh1s.cloudfront.net

## How It Works
1. User enters a phone number or email address.
2. The system sends a request to the respective validation API.
3. The API analyzes the input and returns verification results.
4. The results are displayed to the user.
5. The validation data is stored securely in **AWS DynamoDB** for record keeping.

## Author
**Vaishnavi Kannan**

## License
This project is created for educational and cybersecurity research purposes.
