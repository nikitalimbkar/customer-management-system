const express = require("express");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

require("dotenv").config();

const db = require("./db");

const JWT_SECRET =
    process.env.JWT_SECRET || "fallback_secret_change_this";

const app = express();


// ======================================================
// MIDDLEWARE
// ======================================================

app.use(cors());

app.use(express.json());

app.use(
    express.urlencoded({
        extended: true
    })
);


// ======================================================
// UPLOAD FOLDER
// ======================================================

const uploadFolder = path.join(
    __dirname,
    "uploads"
);

if (!fs.existsSync(uploadFolder)) {
    fs.mkdirSync(uploadFolder, {
        recursive: true
    });
}


// ======================================================
// ALLOWED FILE TYPES
// ======================================================

const allowedExtensions = [
    ".pdf",
    ".jpg",
    ".jpeg",
    ".png",
    ".doc",
    ".docx"
];


// ======================================================
// MULTER CONFIGURATION
// ======================================================

const storage = multer.diskStorage({

    destination: function (req, file, cb) {

        cb(
            null,
            uploadFolder
        );

    },

    filename: function (req, file, cb) {

        const extension =
            path.extname(
                file.originalname
            ).toLowerCase();

        const originalName =
            path.basename(
                file.originalname,
                extension
            );

        const safeName =
            originalName.replace(
                /[^a-zA-Z0-9_-]/g,
                "_"
            );

        const uniqueName =
            Date.now() +
            "-" +
            Math.round(
                Math.random() * 1E9
            ) +
            "-" +
            safeName +
            extension;

        cb(
            null,
            uniqueName
        );

    }

});


const upload = multer({

    storage: storage,

    limits: {
        fileSize:
            10 * 1024 * 1024
    },

    fileFilter:
        function (req, file, cb) {

            const extension =
                path.extname(
                    file.originalname
                ).toLowerCase();

            if (
                allowedExtensions.includes(
                    extension
                )
            ) {

                cb(
                    null,
                    true
                );

            }
            else {

                cb(
                    new Error(
                        "Only PDF, JPG, JPEG, PNG, DOC and DOCX files are allowed"
                    )
                );

            }

        }

});


// ======================================================
// SERVE UPLOADED FILES
// ======================================================

app.use(
    "/uploads",
    express.static(
        uploadFolder
    )
);


// ======================================================
// HOME
// ======================================================

app.get(
    "/",
    (req, res) => {

        res.json({

            message:
                "Customer Management API is running",

            status:
                "success",

            port:
                process.env.PORT || 5000

        });

    }
);


// ======================================================
// LOGIN
// ======================================================

app.post(
    "/api/login",
    async (req, res) => {

        try {

            const {
                username,
                password
            } = req.body;


            // --------------------------------------------------
            // VALIDATION
            // --------------------------------------------------

            if (
                !username ||
                !password
            ) {

                return res.status(400).json({

                    error:
                        "Username and password are required"

                });

            }


            // --------------------------------------------------
            // FIND USER
            // --------------------------------------------------

            const [users] =
                await db.execute(

                    `SELECT
                        user_id,
                        username,
                        password_hash
                     FROM users
                     WHERE username = ?`,

                    [
                        username.trim()
                    ]

                );


            // --------------------------------------------------
            // USER NOT FOUND
            // --------------------------------------------------

            if (
                users.length === 0
            ) {

                return res.status(401).json({

                    error:
                        "Invalid username or password"

                });

            }


            const user =
                users[0];


            // --------------------------------------------------
            // CHECK PASSWORD
            // --------------------------------------------------

            const passwordMatch =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );


            if (!passwordMatch) {

                return res.status(401).json({

                    error:
                        "Invalid username or password"

                });

            }


            // --------------------------------------------------
            // CREATE JWT TOKEN
            // --------------------------------------------------

            const token =
                jwt.sign(

                    {
                        user_id:
                            user.user_id,

                        username:
                            user.username
                    },

                    JWT_SECRET,

                    {
                        expiresIn:
                            "8h"
                    }

                );


            // --------------------------------------------------
            // LOGIN SUCCESS
            // --------------------------------------------------

            res.json({

                message:
                    "Login successful",

                token:
                    token,

                user: {

                    user_id:
                        user.user_id,

                    username:
                        user.username

                }

            });

        }
        catch (error) {

            console.error(
                "LOGIN ERROR:",
                error
            );

            res.status(500).json({

                error:
                    "Login failed"

            });

        }

    }
);


// ======================================================
// AUTHENTICATION MIDDLEWARE
// ======================================================

function authenticateToken(
    req,
    res,
    next
) {

    const authHeader =
        req.headers[
            "authorization"
        ];


    const token =
        authHeader &&
        authHeader.split(" ")[1];


    // --------------------------------------------------
    // NO TOKEN
    // --------------------------------------------------

    if (!token) {

        return res.status(401).json({

            error:
                "Access denied. Please login."

        });

    }


    // --------------------------------------------------
    // VERIFY TOKEN
    // --------------------------------------------------

    jwt.verify(
        token,
        JWT_SECRET,
        (error, user) => {

            if (error) {

                return res.status(403).json({

                    error:
                        "Invalid or expired token"

                });

            }


            req.user =
                user;


            next();

        }
    );

}


// ======================================================
// GET ALL CUSTOMERS
// Supports:
// ?city=Pune
// ?status=NEW
// ?city=Pune&status=NEW
// ======================================================

app.get(
    "/api/customers",
    authenticateToken,
    async (req, res) => {

        try {

            const {
                city,
                status
            } = req.query;


            let sql = `

                SELECT
                    customer_id,
                    name,
                    mobile_number,
                    address,
                    city,
                    mh_number,
                    aadhar_number,
                    current_status,
                    remarks,
                    created_at,
                    updated_at

                FROM customers

                WHERE 1 = 1

            `;


            const params = [];


            // --------------------------------------------------
            // CITY FILTER
            // --------------------------------------------------

            if (
                city &&
                city !== "ALL"
            ) {

                sql += `

                    AND LOWER(city) = LOWER(?)

                `;

                params.push(
                    city
                );

            }


            // --------------------------------------------------
            // STATUS FILTER
            // --------------------------------------------------

            if (
                status &&
                status !== "ALL"
            ) {

                const validStatuses = [

                    "NEW",
                    "RENEW",
                    "PENDING",
                    "REJECTED"

                ];


                if (
                    !validStatuses.includes(
                        status.toUpperCase()
                    )
                ) {

                    return res.status(400).json({

                        error:
                            "Invalid status"

                    });

                }


                sql += `

                    AND current_status = ?

                `;


                params.push(
                    status.toUpperCase()
                );

            }


            sql += `

                ORDER BY customer_id DESC

            `;


            const [customers] =
                await db.execute(
                    sql,
                    params
                );


            res.json(
                customers
            );

        }
        catch (error) {

            console.error(
                "GET CUSTOMERS ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to fetch customers"

            });

        }

    }
);


// ======================================================
// GET ALL CITIES
// Used by frontend city dropdown
// ======================================================

app.get(
    "/api/customers/cities",
    authenticateToken,
    async (req, res) => {

        try {

            const [rows] =
                await db.execute(`

                    SELECT DISTINCT
                        city

                    FROM customers

                    WHERE city IS NOT NULL
                    AND TRIM(city) <> ''

                    ORDER BY city ASC

                `);


            const cities =
                rows.map(
                    row => row.city
                );


            res.json(
                cities
            );

        }
        catch (error) {

            console.error(
                "GET CITIES ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to fetch cities"

            });

        }

    }
);


// ======================================================
// GET ONE CUSTOMER
// ======================================================

app.get(
    "/api/customers/:id",
    authenticateToken,
    async (req, res) => {

        try {

            const customerId =
                req.params.id;


            // ==================================================
            // CUSTOMER
            // ==================================================

            const [customers] =
                await db.execute(`

                    SELECT
                        customer_id,
                        name,
                        mobile_number,
                        address,
                        city,
                        mh_number,
                        aadhar_number,
                        current_status,
                        remarks,
                        created_at,
                        updated_at

                    FROM customers

                    WHERE customer_id = ?

                `, [
                    customerId
                ]);


            if (
                customers.length === 0
            ) {

                return res.status(404).json({

                    error:
                        "Customer not found"

                });

            }


            const customer =
                customers[0];


            // ==================================================
            // DOCUMENTS
            // ==================================================

            const [documents] =
                await db.execute(`

                    SELECT
                        document_id,
                        document_name,
                        document_type,
                        file_path,
                        uploaded_at

                    FROM documents

                    WHERE customer_id = ?

                    ORDER BY document_id DESC

                `, [
                    customerId
                ]);


            // ==================================================
            // STATUS HISTORY
            // ==================================================

            const [history] =
                await db.execute(`

                    SELECT
                        history_id,
                        old_status,
                        new_status,
                        remarks,
                        changed_at

                    FROM status_history

                    WHERE customer_id = ?

                    ORDER BY history_id DESC

                `, [
                    customerId
                ]);


            customer.documents =
                documents;


            customer.status_history =
                history;


            res.json(
                customer
            );

        }
        catch (error) {

            console.error(
                "GET CUSTOMER ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to fetch customer"

            });

        }

    }
);


// ======================================================
// ADD CUSTOMER
// ======================================================

app.post(
    "/api/customers",
    authenticateToken,
    async (req, res) => {

        try {

            const {

                name,
                mobile_number,
                address,
                city,
                mh_number,
                aadhar_number,
                current_status,
                remarks

            } = req.body;


            // ==================================================
            // VALIDATION
            // ==================================================

            if (
                !name ||
                !mobile_number ||
                !address ||
                !city ||
                !mh_number ||
                !aadhar_number
            ) {

                return res.status(400).json({

                    error:
                        "Name, mobile number, address, city, MH number and Aadhaar number are required"

                });

            }


            const status =
                current_status ||
                "NEW";


            const validStatuses = [

                "NEW",
                "RENEW",
                "PENDING",
                "REJECTED"

            ];


            if (
                !validStatuses.includes(
                    status
                )
            ) {

                return res.status(400).json({

                    error:
                        "Invalid application status"

                });

            }


            // ==================================================
            // INSERT CUSTOMER
            // ==================================================

            const [result] =
                await db.execute(`

                    INSERT INTO customers

                    (
                        name,
                        mobile_number,
                        address,
                        city,
                        mh_number,
                        aadhar_number,
                        current_status,
                        remarks
                    )

                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)

                `, [

                    name.trim(),

                    mobile_number.trim(),

                    address.trim(),

                    city.trim(),

                    mh_number.trim(),

                    aadhar_number.trim(),

                    status,

                    remarks
                        ? remarks.trim()
                        : ""

                ]);


            const customerId =
                result.insertId;


            // ==================================================
            // INITIAL STATUS HISTORY
            // ==================================================

            await db.execute(`

                INSERT INTO status_history

                (
                    customer_id,
                    old_status,
                    new_status,
                    remarks
                )

                VALUES (?, ?, ?, ?)

            `, [

                customerId,

                null,

                status,

                remarks
                    ? remarks.trim()
                    : ""

            ]);


            res.status(201).json({

                message:
                    "Customer added successfully",

                customer_id:
                    customerId

            });

        }
        catch (error) {

            console.error(
                "ADD CUSTOMER ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to add customer"

            });

        }

    }
);


// ======================================================
// UPDATE CUSTOMER
// ======================================================

app.put(
    "/api/customers/:id",
    authenticateToken,
    async (req, res) => {

        try {

            const customerId =
                req.params.id;


            const {

                name,
                mobile_number,
                address,
                city,
                mh_number,
                aadhar_number,
                current_status,
                remarks

            } = req.body;


            // ==================================================
            // VALIDATION
            // ==================================================

            if (
                !name ||
                !mobile_number ||
                !address ||
                !city ||
                !mh_number ||
                !aadhar_number ||
                !current_status
            ) {

                return res.status(400).json({

                    error:
                        "All required fields must be filled"

                });

            }


            const validStatuses = [

                "NEW",
                "RENEW",
                "PENDING",
                "REJECTED"

            ];


            if (
                !validStatuses.includes(
                    current_status
                )
            ) {

                return res.status(400).json({

                    error:
                        "Invalid application status"

                });

            }


            // ==================================================
            // GET OLD CUSTOMER
            // ==================================================

            const [oldCustomer] =
                await db.execute(`

                    SELECT
                        current_status

                    FROM customers

                    WHERE customer_id = ?

                `, [
                    customerId
                ]);


            if (
                oldCustomer.length === 0
            ) {

                return res.status(404).json({

                    error:
                        "Customer not found"

                });

            }


            const oldStatus =
                oldCustomer[0]
                    .current_status;


            // ==================================================
            // UPDATE CUSTOMER
            // ==================================================

            await db.execute(`

                UPDATE customers

                SET

                    name = ?,

                    mobile_number = ?,

                    address = ?,

                    city = ?,

                    mh_number = ?,

                    aadhar_number = ?,

                    current_status = ?,

                    remarks = ?

                WHERE customer_id = ?

            `, [

                name.trim(),

                mobile_number.trim(),

                address.trim(),

                city.trim(),

                mh_number.trim(),

                aadhar_number.trim(),

                current_status,

                remarks
                    ? remarks.trim()
                    : "",

                customerId

            ]);


            // ==================================================
            // STATUS CHANGED?
            // ==================================================

            if (
                oldStatus !==
                current_status
            ) {

                await db.execute(`

                    INSERT INTO status_history

                    (
                        customer_id,
                        old_status,
                        new_status,
                        remarks
                    )

                    VALUES (?, ?, ?, ?)

                `, [

                    customerId,

                    oldStatus,

                    current_status,

                    remarks
                        ? remarks.trim()
                        : ""

                ]);

            }


            res.json({

                message:
                    "Customer updated successfully"

            });

        }
        catch (error) {

            console.error(
                "UPDATE CUSTOMER ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to update customer"

            });

        }

    }
);


// ======================================================
// CHANGE STATUS
// ======================================================

app.put(
    "/api/customers/:id/status",
    authenticateToken,
    async (req, res) => {

        try {

            const customerId =
                req.params.id;


            const {
                status,
                remarks
            } = req.body;


            // ==================================================
            // VALID STATUSES
            // ==================================================

            const validStatuses = [

                "NEW",
                "RENEW",
                "PENDING",
                "REJECTED"

            ];


            if (
                !validStatuses.includes(
                    status
                )
            ) {

                return res.status(400).json({

                    error:
                        "Invalid status"

                });

            }


            // ==================================================
            // GET OLD STATUS
            // ==================================================

            const [customer] =
                await db.execute(`

                    SELECT
                        current_status

                    FROM customers

                    WHERE customer_id = ?

                `, [
                    customerId
                ]);


            if (
                customer.length === 0
            ) {

                return res.status(404).json({

                    error:
                        "Customer not found"

                });

            }


            const oldStatus =
                customer[0]
                    .current_status;


            // ==================================================
            // UPDATE STATUS
            // ==================================================

            await db.execute(`

                UPDATE customers

                SET
                    current_status = ?

                WHERE customer_id = ?

            `, [

                status,

                customerId

            ]);


            // ==================================================
            // SAVE STATUS HISTORY
            // ==================================================

            await db.execute(`

                INSERT INTO status_history

                (
                    customer_id,
                    old_status,
                    new_status,
                    remarks
                )

                VALUES (?, ?, ?, ?)

            `, [

                customerId,

                oldStatus,

                status,

                remarks
                    ? remarks.trim()
                    : ""

            ]);


            res.json({

                message:
                    "Status updated successfully"

            });

        }
        catch (error) {

            console.error(
                "CHANGE STATUS ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to change status"

            });

        }

    }
);


// ======================================================
// DELETE CUSTOMER
// ======================================================

app.delete(
    "/api/customers/:id",
    authenticateToken,
    async (req, res) => {

        try {

            const customerId =
                req.params.id;


            // ==================================================
            // GET CUSTOMER DOCUMENTS FIRST
            // ==================================================

            const [documents] =
                await db.execute(`

                    SELECT
                        file_path

                    FROM documents

                    WHERE customer_id = ?

                `, [
                    customerId
                ]);


            // ==================================================
            // DELETE CUSTOMER
            // ==================================================

            const [result] =
                await db.execute(`

                    DELETE FROM customers

                    WHERE customer_id = ?

                `, [
                    customerId
                ]);


            if (
                result.affectedRows === 0
            ) {

                return res.status(404).json({

                    error:
                        "Customer not found"

                });

            }


            // ==================================================
            // DELETE ACTUAL FILES
            // ==================================================

            documents.forEach(
                document => {

                    if (
                        document.file_path
                    ) {

                        const actualFile =
                            path.join(
                                __dirname,
                                document.file_path.replace(
                                    "/uploads/",
                                    "uploads/"
                                )
                            );


                        if (
                            fs.existsSync(
                                actualFile
                            )
                        ) {

                            try {

                                fs.unlinkSync(
                                    actualFile
                                );

                            }
                            catch (
                                fileError
                            ) {

                                console.error(
                                    "Could not delete file:",
                                    fileError
                                );

                            }

                        }

                    }

                }
            );


            res.json({

                message:
                    "Customer deleted successfully"

            });

        }
        catch (error) {

            console.error(
                "DELETE CUSTOMER ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to delete customer"

            });

        }

    }
);


// ======================================================
// UPLOAD DOCUMENT
// ======================================================

app.post(
    "/api/customers/:id/documents",
    authenticateToken,
    upload.single("document"),

    async (req, res) => {

        try {

            const customerId =
                req.params.id;


            // ==================================================
            // CHECK CUSTOMER
            // ==================================================

            const [customer] =
                await db.execute(`

                    SELECT
                        customer_id

                    FROM customers

                    WHERE customer_id = ?

                `, [
                    customerId
                ]);


            if (
                customer.length === 0
            ) {

                if (
                    req.file &&
                    req.file.path
                ) {

                    try {

                        fs.unlinkSync(
                            req.file.path
                        );

                    }
                    catch (
                        fileError
                    ) {

                        console.error(
                            fileError
                        );

                    }

                }


                return res.status(404).json({

                    error:
                        "Customer not found"

                });

            }


            // ==================================================
            // CHECK FILE
            // ==================================================

            if (!req.file) {

                return res.status(400).json({

                    error:
                        "Please select a document"

                });

            }


            const documentType =
                req.body.document_type ||
                "Customer Document";


            // ==================================================
            // SAVE DOCUMENT DETAILS
            // ==================================================

            const [result] =
                await db.execute(`

                    INSERT INTO documents

                    (
                        customer_id,
                        document_name,
                        document_type,
                        file_path
                    )

                    VALUES (?, ?, ?, ?)

                `, [

                    customerId,

                    req.file.originalname,

                    documentType,

                    `/uploads/${req.file.filename}`

                ]);


            res.status(201).json({

                message:
                    "Document uploaded successfully",

                document_id:
                    result.insertId,

                document_name:
                    req.file.originalname,

                file_url:
                    `/uploads/${req.file.filename}`

            });

        }
        catch (error) {

            console.error(
                "UPLOAD DOCUMENT ERROR:",
                error
            );


            // Delete uploaded file if database insert fails

            if (
                req.file &&
                req.file.path
            ) {

                try {

                    if (
                        fs.existsSync(
                            req.file.path
                        )
                    ) {

                        fs.unlinkSync(
                            req.file.path
                        );

                    }

                }
                catch (
                    fileError
                ) {

                    console.error(
                        fileError
                    );

                }

            }


            res.status(500).json({

                error:
                    "Failed to upload document"

            });

        }

    }
);


// ======================================================
// GET DOCUMENTS
// ======================================================

app.get(
    "/api/customers/:id/documents",
    authenticateToken,
    async (req, res) => {

        try {

            const customerId =
                req.params.id;


            const [documents] =
                await db.execute(`

                    SELECT

                        document_id,

                        document_name,

                        document_type,

                        file_path,

                        uploaded_at

                    FROM documents

                    WHERE customer_id = ?

                    ORDER BY document_id DESC

                `, [
                    customerId
                ]);


            res.json(
                documents
            );

        }
        catch (error) {

            console.error(
                "GET DOCUMENTS ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to fetch documents"

            });

        }

    }
);


// ======================================================
// DELETE DOCUMENT
// ======================================================

app.delete(
    "/api/documents/:id",
    authenticateToken,
    async (req, res) => {

        try {

            const documentId =
                req.params.id;


            // ==================================================
            // GET FILE PATH
            // ==================================================

            const [documents] =
                await db.execute(`

                    SELECT
                        file_path

                    FROM documents

                    WHERE document_id = ?

                `, [
                    documentId
                ]);


            if (
                documents.length === 0
            ) {

                return res.status(404).json({

                    error:
                        "Document not found"

                });

            }


            const filePath =
                documents[0]
                    .file_path;


            // ==================================================
            // DELETE DATABASE RECORD
            // ==================================================

            await db.execute(`

                DELETE FROM documents

                WHERE document_id = ?

            `, [
                documentId
            ]);


            // ==================================================
            // DELETE ACTUAL FILE
            // ==================================================

            const actualFile =
                path.join(
                    __dirname,
                    filePath.replace(
                        "/uploads/",
                        "uploads/"
                    )
                );


            if (
                fs.existsSync(
                    actualFile
                )
            ) {

                fs.unlinkSync(
                    actualFile
                );

            }


            res.json({

                message:
                    "Document deleted successfully"

            });

        }
        catch (error) {

            console.error(
                "DELETE DOCUMENT ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to delete document"

            });

        }

    }
);


// ======================================================
// DASHBOARD COUNTS
// ======================================================

app.get(
    "/api/dashboard",
    authenticateToken,
    async (req, res) => {

        try {

            const [rows] =
                await db.execute(`

                    SELECT

                        COUNT(*) AS total,

                        SUM(
                            current_status = 'NEW'
                        ) AS new_count,

                        SUM(
                            current_status = 'RENEW'
                        ) AS renew_count,

                        SUM(
                            current_status = 'PENDING'
                        ) AS pending_count,

                        SUM(
                            current_status = 'REJECTED'
                        ) AS rejected_count

                    FROM customers

                `);


            const data =
                rows[0];


            res.json({

                total:
                    Number(
                        data.total || 0
                    ),

                new_count:
                    Number(
                        data.new_count || 0
                    ),

                renew_count:
                    Number(
                        data.renew_count || 0
                    ),

                pending_count:
                    Number(
                        data.pending_count || 0
                    ),

                rejected_count:
                    Number(
                        data.rejected_count || 0
                    )

            });

        }
        catch (error) {

            console.error(
                "DASHBOARD ERROR:",
                error
            );


            res.status(500).json({

                error:
                    "Failed to fetch dashboard"

            });

        }

    }
);


// ======================================================
// MULTER / GENERAL ERROR HANDLER
// ======================================================

app.use(
    (error, req, res, next) => {

        if (
            error instanceof
            multer.MulterError
        ) {

            if (
                error.code ===
                "LIMIT_FILE_SIZE"
            ) {

                return res.status(400).json({

                    error:
                        "File size must be 10 MB or less"

                });

            }


            return res.status(400).json({

                error:
                    error.message

            });

        }


        if (
            error &&
            error.message &&
            error.message.includes(
                "Only PDF"
            )
        ) {

            return res.status(400).json({

                error:
                    error.message

            });

        }


        console.error(
            "SERVER ERROR:",
            error
        );


        res.status(500).json({

            error:
                "Something went wrong"

        });

    }
);


// ======================================================
// START SERVER
// ======================================================

const PORT =
    process.env.PORT || 5000;


app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Server running on port ${PORT}`
        );

        console.log(
            `http://localhost:${PORT}`
        );

    }
);