## DynamoDB localメモ
※インストール参考  
dockerでは入れず、zipファイルから落としてる  
https://qiita.com/gzock/items/e0225fd71917c234acce  
  
■実行コマンド  
java -Djava.library.path=./DynamoDBLocal_lib -jar DynamoDBLocal.jar -sharedDb  
  
■GUIの起動  
dynamodb-admin  

■CLIでの使用例  

```bash
# テーブル一覧の出力
aws dynamodb  --endpoint-url http://localhost:8000 `
 list-tables

# scan例
aws dynamodb  --endpoint-url http://localhost:8000 `
 scan `
 --table-name GameTable `
 --filter-expression "gameCategory = :category" `
 --expression-attribute-values '{\":category\":{\"S\":\"RPG\"}}' `
 --output yaml
```

## Micronaut 3.5.0 Documentation

- [User Guide](https://docs.micronaut.io/3.5.0/guide/index.html)
- [API Reference](https://docs.micronaut.io/3.5.0/api/index.html)
- [Configuration Reference](https://docs.micronaut.io/3.5.0/guide/configurationreference.html)
- [Micronaut Guides](https://guides.micronaut.io/index.html)
---

## Deployment with GraalVM

If you want to deploy to AWS Lambda as a GraalVM native image, run:

```bash
./gradlew buildNativeLambda -Pmicronaut.runtime=lambda
```

This will build the GraalVM native image inside a docker container and generate the `function.zip` ready for the deployment.


## Handler

[AWS Lambda Handler](https://docs.aws.amazon.com/lambda/latest/dg/java-handler.html)

Handler: example.micronaut.FunctionRequestHandler


- [Shadow Gradle Plugin](https://plugins.gradle.org/plugin/com.github.johnrengelman.shadow)
## Feature aws-lambda-custom-runtime documentation

- [Micronaut Custom AWS Lambda runtime documentation](https://micronaut-projects.github.io/micronaut-aws/latest/guide/index.html#lambdaCustomRuntimes)

- [https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html)


## Feature http-client documentation

- [Micronaut HTTP Client documentation](https://docs.micronaut.io/latest/guide/index.html#httpClient)


## Feature aws-lambda documentation

- [Micronaut AWS Lambda Function documentation](https://micronaut-projects.github.io/micronaut-aws/latest/guide/index.html#lambda)


