# Welcome to pkg-auth

`pkg-auth` is a clean-architecture authentication and authorization core for Python frameworks. It provides a framework-agnostic facade for handling token-based security, with first-class integrations for FastAPI and Strawberry GraphQL.

## Getting Started

If you're new to `pkg-auth`, we recommend starting with the following pages:

- **[Installation](Installation)**: Learn how to install `pkg-auth` in your project.
- **[User Guide](User-Guide)**: Understand the key concepts and how to use the core `AuthDependencies` object.

## Integrations

`pkg-auth` provides seamless integrations with popular Python frameworks:

- **[FastAPI](FastAPI-Integration)**: Secure your FastAPI routes using dependency injection or decorators.
- **[Strawberry GraphQL](Strawberry-GraphQL-Integration)**: Protect your GraphQL schema with permission classes.

## How It Works

`pkg-auth` is designed to work with [Keycloak](https://www.keycloak.org/), an open-source identity and access management solution. It uses JSON Web Tokens (JWTs) to securely transmit information between parties.

The core of the package is the `AuthDependencies` object, which provides a framework-agnostic way to handle authentication and authorization. The integrations for FastAPI and Strawberry GraphQL are built on top of this core, providing a convenient and idiomatic way to secure your applications.
