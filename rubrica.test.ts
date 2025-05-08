import { expect, test, describe, afterAll, afterEach, beforeEach, onTestFinished } from 'vitest'
import { randomUUID } from 'node:crypto'
import request from 'supertest'
import app from './index.js'

interface User {
	name: string
	username: string
	token: string
	password?: string
}

interface Reminder {
	id?: string
	content?: string
	important?: boolean
}

function loginRequest(username = 'admin', password = 'certamen123') {
	return request(app)
		.post('/api/auth/login')
		.send({ username, password })
}

async function loginAndSetToken(context: any) {
	const { body } = await loginRequest()
	context.token = body.token
}

function createReminderRequest(content: string, important?: boolean, token: string = '') {
	return request(app)
		.post('/api/reminders')
		.set('X-Authorization', token)
		.send({ content, important })
}

function updateItemRequest(id: string, attrs: Reminder, token: string = '') {
	return request(app)
		.patch('/api/reminders/' + id)
		.set('X-Authorization', token)
		.send(attrs)
}

function deleteRequest(id: string, token: string = '') {
	return request(app)
		.delete('/api/reminders/' + id)
		.set('X-Authorization', token)
}

function getAllReminders(token: string = '') {
	return request(app)
		.get('/api/reminders')
		.set('X-Authorization', token)
}

let totalPoints = 0
let minusPoints = 0

function count() {
	onTestFinished(result => {
		const state = expect.getState()
		totalPoints += state.assertionCalls	
		minusPoints += result.task.result?.errors?.length ?? 0
	})
}

afterEach(count)

afterAll(() => {

	const maxPoints = 40

	if (totalPoints !== maxPoints) {
		console.error(`Something went wrong D:! Total Points: ${totalPoints} !== Max Points: ${maxPoints}`)
	}

	const studentPoints = maxPoints - minusPoints
	console.log(`Puntos: ${studentPoints}/${maxPoints}`)
	console.log(`Nota ${(
		studentPoints < 0.51 * maxPoints 
		? (4-1) * studentPoints / (0.51 * maxPoints) + 1 
		: (7 - 4) * (studentPoints - 0.51 * maxPoints) / (maxPoints * (1 - 0.51)) + 4).toFixed(1)}`
	)
})

describe('POST /api/auth/login', async (context) => {
	
	test('Se loguea correctamente', async () => {
		const { body, status, headers } = await loginRequest()

		expect.soft(status).toBe(200)
		expect.soft(body.name).toBe('Gustavo Alfredo Marín Sáez')
		expect.soft(body.username).toBe('admin')
		expect.soft(body.token).toBeTypeOf('string')
		expect.soft(body.token).toMatch(/^[0-9a-f]+$/i)
		expect.soft(body.password).toBeTypeOf('undefined')
	})

	test('El token es distinto con cada logueo', async () => {
		const { body: login1 } = await loginRequest()
		const { body: login2 } = await loginRequest()

		expect.soft(login1.token).not.toBe(login2.token) // 1
	})

	test('Devuelve código de estado 400 cuando no se envían los datos apropiados', async () => {
		const { status: loginStatus } = await loginRequest(123, false)
		
		expect.soft(loginStatus).toBe(400)
	})

	test('Devuelve código de estado 401 cuando el usuario no existe o contraseña incorrecta', async () => {
		const { status: loginStatus1 } = await loginRequest('notadmin', 'certamen123')
		const { status: loginStatus2 } = await loginRequest('admin', 'certamen1234')

		expect.soft(loginStatus1).toBe(401)
		expect.soft(loginStatus2).toBe(401)
	})
})

describe('GET /api/reminders', async () => {

	beforeEach(loginAndSetToken)

	test('Lista recordatorios', async ({ token }) => {
		const { body, status } = await getAllReminders(token)

		expect.soft(status, 'Código de estado 200').toBe(200)
		expect.soft(Array.isArray(body), 'Es un arreglo').toBe(true)
		expect.soft(body?.length, 'Es un arreglo').toBe(0)
	})
})

describe('POST /api/reminders', async () => {

	beforeEach(loginAndSetToken)
	
	test('Crea un recordatorio correctamente', async ({ token }) => {
		const { body: createdItem1, status: statusItem1 } = await createReminderRequest('Item 1', true, token)

		expect.soft(createdItem1.id).toBeTypeOf('string')
		expect.soft(createdItem1.content).toBe('Item 1')
		expect.soft(createdItem1.important).toBe(true)
		expect.soft(createdItem1.createdAt).toBeTypeOf('number')
		expect.soft(statusItem1).toBe(201)
	})

	test('Crea un recordatorio correctamente con importante default', async ({ token }) => {
		const { body: createdItem1, status: statusItem1 } = await createReminderRequest('Item 2', undefined, token)

		expect.soft(createdItem1.important).toBe(false)
	})

	test('Devuelve código de estado 400 cuando no se envían los datos apropiados', async ({ token }) => {
		const { status: statusItem3 } = await createReminderRequest(false, true, token)
		const { status: statusItem4 } = await createReminderRequest('Item 4', 26, token)

		expect.soft(statusItem3).toBe(400)
		expect.soft(statusItem4).toBe(400)
	})

	test('Persiste el item creado previamente', async ({ token }) => {
		const { body: createdItem5 } = await createReminderRequest('Item 5', undefined, token)

		const { body: reminders } = await getAllReminders(token)
	
		expect.soft(reminders?.find(reminder => reminder.id === createdItem5.id)).toMatchObject({
			content: 'Item 5'
		})
	})
})

describe('PATCH /api/reminders/[id]', () => {

	beforeEach(loginAndSetToken)

	test('Actualiza un item correctamente', async ({ token }) => {

		const { body: createdItem6 } = await createReminderRequest('Item 6', true, token)
	
		const firstUpdate = {
			content: 'Item 6 UPDATED'
		}
		
		const { body: updatedItem1, status: statusUpdatedItem1 } = await updateItemRequest(createdItem6.id, firstUpdate, token)
	
		expect.soft(statusUpdatedItem1, "Dar un código 200 al actualizar el título").toBe(200)
		expect.soft(updatedItem1, "El objeto retornado tiene el título actualizado").toMatchObject(firstUpdate)
	
		const secondUpdate = {
			content: 'Item 6 UPDATED 2',
			important: true
		}
	
		const { body: updatedItem2, status: statusUpdatedItem2 } = await updateItemRequest(createdItem6.id, secondUpdate, token)
	
		expect.soft(statusUpdatedItem2, "Dar un código 200 al actualizar el título y el estado").toBe(200)
		expect.soft(updatedItem2, "El objeto retornado tiene el título y el estado actualizado").toMatchObject(secondUpdate)
	
		const { body: reminders } = await getAllReminders(token)
	
		expect.soft(reminders?.find(reminder => reminder.id === updatedItem2.id)).toMatchObject(secondUpdate)
	})

	test('Devuelve código de estado 400 cuando no se envían los datos apropiados', async ({ token }) => {
		const { body: createdItem7 } = await createReminderRequest('Item 7', false, token)

		const { status: updateStatus1 } = await updateItemRequest(createdItem7.id, { content: 123 }, token)
		expect.soft(updateStatus1).toBe(400)

		const { status: updateStatus2 } = await updateItemRequest(createdItem7.id, { important: 'HELLO WORLD!' }, token)
		expect.soft(updateStatus2).toBe(400)
	})

	test('Devuelve código de estado 404 cuando el ítem a actualizar no existe', async ({ token }) => {
		const { status: updateStatus1 } = await updateItemRequest(randomUUID(), { content: 'Hello World!' }, token)

		expect.soft(updateStatus1).toBe(404)
	})
})

describe('DELETE /api/reminders/[id]', () => {

	beforeEach(loginAndSetToken)

	test('Borra un item correctamente', async ({ token }) => {
		const { body: createdItem5 } = await createReminderRequest('Item 5', undefined, token)

		const { body: deletedItem1, status: deleteStatus1 } = await deleteRequest(createdItem5.id, token)

		
		expect.soft(Object.keys(deletedItem1).length).toBe(0)
		expect.soft(deleteStatus1).toBe(204)

		const { body: reminders } = await getAllReminders(token)

		expect.soft(reminders?.find(reminder => reminder.id === createdItem5.id)).toBeUndefined()
	})

	test('Devuelve código de estado 404 cuando el ítem a borrar no existe', async ({ token }) => {
		const { status: deleteStatus1 } = await deleteRequest(randomUUID(), token)

		expect.soft(deleteStatus1).toBe(404)
	})
})

test('Los endpoints indicados están protegidos por un token de autenticación', async ({ token }) => {
	const { status: listStatus } = await getAllReminders()
	const { status: createStatus } = await createReminderRequest('ITEM')
	const { status: updateStatus } = await updateItemRequest(randomUUID(), { content: 'UPDAte' })
	const { status: deleteStatus } = await deleteRequest(randomUUID())

	expect.soft(listStatus).toBe(401)
	expect.soft(createStatus).toBe(401)
	expect.soft(updateStatus).toBe(401)
	expect.soft(deleteStatus).toBe(401)
})

describe('GET /api/reminders', async () => {

	beforeEach(loginAndSetToken)

	test('Lista recordatorios en el orden indicado', async ({ token }) => {
		const { body: reminders } = await getAllReminders(token)

		const sortedReminders = reminders.toSorted((a, b) => {
			if (a.important && !b.important)  {
				return -1;
			}
			else if (!a.important && b.important) {
				return 1;
			}
			return a.createdAt - b.createdAt;
		})

		expect.soft(JSON.stringify(reminders)).toBe(JSON.stringify(sortedReminders))
		expect.soft(JSON.stringify(reminders)).toBe(JSON.stringify(sortedReminders)) // two points
	})
})