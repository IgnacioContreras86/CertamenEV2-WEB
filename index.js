import express from "express";
import { randomUUID, scrypt, randomBytes } from "crypto";
import { object, string, boolean, minLength, maxLength, optional, parse } from "valibot";

const PORT = process.env.PORT ?? 3000;

const app = express();
const users = [
	{
		username: "admin",
		name: "Gustavo Alfredo Marín Sáez",
		password:
			"1b6ce880ac388eb7fcb6bcaf95e20083:341dfbbe86013c940c8e898b437aa82fe575876f2946a2ad744a0c51501c7dfe6d7e5a31c58d2adc7a7dc4b87927594275ca235276accc9f628697a4c00b4e01", // certamen123
	},
];

// Esquemas de validación con Valibot
const loginSchema = object({
    username: string([minLength(1)]),
    password: string([minLength(1)])
});

const reminderSchema = object({
    content: string([minLength(1), maxLength(120)]),
    important: optional(boolean())
});

const updateReminderSchema = object({
    content: optional(string([minLength(1), maxLength(120)])),
    important: optional(boolean())
});

// Middleware de validación
function validateSchema(schema) {
    return (req, res, next) => {
        try {
            req.body = parse(schema, req.body);
            next();
        } catch (error) {
            res.status(400).json({
                error: error.message
            });
        }
    };
}

app.use(express.static("public"));
// Escriba su código a partir de aquí

export const reminders = []

app.use(express.json());

function authMiddleware(req, res, next) {
	const token = req.get("X-Authorization");

	if (!token) {
		return res.status(401).json({
			error: "No se ha proporcionado un token de autorización",
		});
	}

	const user = users.find(user => user.token === token)

	if (!user) {
		return res.status(401).json({
			error: "El token es inválido"
		})
	}

	next()
}

function hashPasswordWithSalt(password, salt) {
	return new Promise((resolve, reject) => {
		scrypt(password, salt, 64, (err, derivedKey) => {
			if (err) {
				return reject(err);
			}
			resolve(`${salt}:${derivedKey.toString("hex")}`);
		});
	});
}

function hashPassword(password) {
	const salt = randomBytes(16).toString("hex");

	return hashPasswordWithSalt(password, salt)
}

async function verifyPassword(password, hash) {
	const [salt] = hash.split(":");
	
	try {
		const hashedPassword = await hashPasswordWithSalt(password, salt);
		return hashedPassword === hash;
	} catch {
		return false;
	}
}

app.post("/api/auth/login", validateSchema(loginSchema), async (req, res) => {
	const { username, password } = req.body;

	const user = users.find((user) => user.username === username);

	if (!user) {
		return res.status(401).json({
			error: "Nombre de usuario o contraseña incorrectos :(",
		});
	}

	if (!await verifyPassword(password, user.password)) {
		return res.status(401).json({
			error: "Nombre de usuario o contraseña incorrectos",
		});
	}
	
	user.token = randomBytes(48).toString("hex");

	res.json({
		username: user.username,
		token: user.token,
		name: user.name
	});
})

app.get("/api/reminders", authMiddleware, (req, res) => {
	res.json(reminders.toSorted((a, b) => {
		if (a.important && !b.important)  {
			return -1;
		}
		else if (!a.important && b.important) {
			return 1;
		}
		return a.createdAt - b.createdAt;
	}))
})

app.post("/api/reminders", authMiddleware, validateSchema(reminderSchema), (req, res) => {
	const { content, important } = req.body;

	const newReminder = {
		id: randomUUID(),
		content: content.trim(),
		createdAt: Date.now(),
		important: important ?? false,
	};

	reminders.push(newReminder);
	res.status(201).json(newReminder);
})

app.patch("/api/reminders/:id", authMiddleware, validateSchema(updateReminderSchema), (req, res) => {
	const { id } = req.params;
	const { content, important } = req.body;

	const reminder = reminders.find((reminder) => reminder.id === id);

	if (!reminder) {
		return res.status(404).json({
			error: "Recordatorio no encontrado",
		});
	}

	if (content !== undefined) {
		reminder.content = content.trim();
	}

	if (important !== undefined) {
		reminder.important = important;
	}

	res.json(reminder);
})

app.delete("/api/reminders/:id", authMiddleware, (req, res) => {
	const { id } = req.params;

	const reminderIndex = reminders.findIndex((reminder) => reminder.id === id);

	if (reminderIndex === -1) {
		return res.status(404).json({
			error: "Recordatorio no encontrado",
		});
	}

	reminders.splice(reminderIndex, 1);

	res.status(204).end();
})

// Hasta aquí

app.listen(PORT, (error) => {
	if (error) {
		console.error(`No se puede ocupar el puerto ${PORT} :(`);
		return;
	}

	console.log(`Escuchando en el puerto ${PORT}`);
});

export default app
