package com.uid2.core.handler;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;

public class ExceptionFilterBodyHandler implements Handler<RoutingContext> {

    BodyHandler bodyHandler = BodyHandler.create();

    @Override
    public void handle(RoutingContext rc) {
        try {
            bodyHandler.handle(rc);
        } catch (IllegalStateException e) {
            if(e.getMessage().equalsIgnoreCase("Request method must be one of POST, PUT, PATCH or DELETE to decode a multipart request")) {
                rc.response().setStatusCode(400).end("Content-Type \"multipart/*\" Not Allowed\"");
            } else {
                throw e;
            }
        }
    }
}
