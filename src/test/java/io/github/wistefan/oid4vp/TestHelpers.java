package io.github.wistefan.oid4vp;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.function.BiFunction;
import java.util.function.Function;

public class TestHelpers {

    public <P1, P2, T> T executeWithUnwrapping(P1 parameterOne, P2 parameterTwo, BiFunction<P1, P2, CompletableFuture<T>> functionToExecute) throws Throwable {
        try {
            return functionToExecute.apply(parameterOne, parameterTwo).get();
        } catch (CompletionException | ExecutionException e) {
            throw e.getCause();
        }
    }

    public <P, T> T executeWithUnwrapping(P parameter, Function<P, CompletableFuture<T>> functionToExecute) throws Throwable {
        try {
            return functionToExecute.apply(parameter).get();
        } catch (CompletionException | ExecutionException e) {
            throw e.getCause();
        }
    }
}
