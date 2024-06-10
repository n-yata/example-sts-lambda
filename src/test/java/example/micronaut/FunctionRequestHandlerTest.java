package example.micronaut;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import example.micronaut.domain.FuncRequest;
import example.micronaut.domain.GameTable;
import io.micronaut.test.extensions.junit5.annotation.MicronautTest;
import jakarta.inject.Inject;

@MicronautTest
public class FunctionRequestHandlerTest {

    @Inject
    private FunctionRequestHandler handler;
    @Inject
    private ObjectMapper objectMapper;

    APIGatewayProxyRequestEvent request = new APIGatewayProxyRequestEvent();
    FuncRequest rec;
    GameTable game;

    @BeforeEach
    void beforeEach() throws JsonProcessingException {
        rec = new FuncRequest();
        game = new GameTable();

        rec.setAction("get");
        rec.setGameTablie(game);
        game.setGameCategory("RPG");
        game.setGameId("1001");
        game.setGameTitle("Pokemon");
        game.setPublishDate("2023-10-08");

        request.setBody(objectMapper.writeValueAsString(rec));
    }

    @Test
    public void testGet() {
        handler.execute(request);
    }

    @Test
    public void testPut() throws JsonProcessingException {
        rec.setAction("put");
        game.setGameId("1002");
        game.setGameTitle("Mother");
        game.setPublishDate("2022-10-08");
        request.setBody(objectMapper.writeValueAsString(rec));

        handler.execute(request);
    }

    @Test
    public void testQuery() throws JsonProcessingException {
        rec.setAction("query");
        game.setGameId("1002");
        game.setGameTitle("Mother");
        game.setPublishDate("2022-10-08");
        request.setBody(objectMapper.writeValueAsString(rec));

        handler.execute(request);
    }

    @Test
    public void testDelete() throws JsonProcessingException {
        rec.setAction("delete");
        game.setGameCategory("RPG");
        game.setGameId("1002");
        request.setBody(objectMapper.writeValueAsString(rec));

        handler.execute(request);
    }
}
