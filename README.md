## Keycloack mapper plugin: Implements native AWS methods for script

_Adds new script-based mapper functionality with native functions for aws lambda_

![alt text](docs/mapper.png)

## Instalation

`docker cp keycloak-mapper-aws-lambda-script-1.0-SNAPSHOT.jar keycloack:/opt/jboss/keycloak/standalone/deployments/`

## Code example

```javascript
/**
 * Available variables: 
 * user - the current user
 * realm - the current realm
 * token - the current token
 * userSession - the current userSession
 * keycloakSession - the current keycloakSession
 * lambda - the lambda instance from aws
 */

var email = user.getFirstAttribute("email");

var inputJSON = JSON.stringify({ email: email });

var result = lambda.invoke("function-name", inputJSON);

var resultObject = JSON.parse(result);

exports = resultObject;

```

## Reference

https://github.com/keycloak/keycloak/blob/main/services/src/main/java/org/keycloak/protocol/oidc/mappers/ScriptBasedOIDCProtocolMapper.java
