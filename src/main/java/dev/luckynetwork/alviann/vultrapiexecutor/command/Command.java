package dev.luckynetwork.alviann.vultrapiexecutor.command;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class Command {

    private final String command;
    private final String[] arguments;

}
