const bcrypt = require("bcryptjs");
const db = require("./db");

async function createUser() {
    try {
        const username = "vijaylimbkar1980@gmail.com";
        const password = "vijay@1980";

        const passwordHash = await bcrypt.hash(password, 10);

        await db.execute(
            `INSERT INTO users (username, password_hash)
             VALUES (?, ?)`,
            [username, passwordHash]
        );

        console.log("User created successfully!");
        console.log("Username:", username);
        console.log("Password:", password);

        process.exit(0);

    } catch (error) {
        console.error("Error creating user:", error);
        process.exit(1);
    }
}

createUser();