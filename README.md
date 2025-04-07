# Getting Started
[!WARNING]
Current branch - 'shared-session', contains an implementation, using the HttpSessions, stored in Redis repository.

0. Install Redis as described in the [Official Documentation](https://redis.io/docs/latest/operate/oss_and_stack/install/install-redis/), or just take any applicable Docker image on [Docker Hub](https://hub.docker.com/).
1. Change settings in YAML file according to your setup.
2. Set app.authorization-server.google.client-secret & app.authorization-server.google.client-id
3. Run project: mvn spring-boot:run
4. Call localhost:8080/oauth2/authorize?client_id=stateless-social&response_type=code&response_mode=query&provider=google&redirect_uri=https://social.talochk.in
5. You'll be landed on the non-existing resource, which could be e.g. your PWA application!
6. ![url_code.png](url_code.png)
7. Type in `redis-cli` to connect to your repository. Then use the command `keys *` to find saved user's session. Session key looks similar to `"social:login:sessions:13867341-4e88-462c-8ec0-8e7c195f456d"`, where `13867341-4e88-462c-8ec0-8e7c195f456d` corresponds the Base64 encoded session cookie value. 
8. Copy Code parameter value.
9. Exchange code to the Access&Refresh tokens, using the Postman collection request.

