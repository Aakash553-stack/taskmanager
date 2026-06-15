# Task Manager REST API

A RESTful API built with Java and Spring Boot that performs full CRUD operations on tasks. Uses an in-memory H2 database for data persistence.

## Features
- Create new tasks with title and description
- Retrieve all tasks or a single task by ID
- Update tasks and mark them as complete
- Delete tasks
- JSON request and response format
- In-memory database (no setup required)

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/tasks | Get all tasks |
| GET | /api/tasks/{id} | Get task by ID |
| POST | /api/tasks | Create a new task |
| PUT | /api/tasks/{id} | Update a task |
| DELETE | /api/tasks/{id} | Delete a task |

## Example Request

POST /api/tasks
{
"title": "Learn Spring Boot",
"description": "Build a REST API with Java",
"completed": false
}

## What I Learned
- Spring Boot framework and project structure
- REST API design with proper HTTP methods
- Spring Data JPA for database operations
- Connecting a Java app to a database with zero SQL
- Testing APIs with Postman

## Technologies
- Java 21
- Spring Boot 3.5.15
- Spring Data JPA
- H2 In-Memory Database
- Maven
- Postman (for testing)