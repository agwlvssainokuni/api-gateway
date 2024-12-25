/*
 * Copyright 2022,2024 agwlvssainokuni
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cherry.apigateway.controller;

import org.springframework.boot.ExitCodeGenerator;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

@RestController
public class ExitController implements ExitCodeGenerator {

    private Integer exitCode = null;

    @RequestMapping("/exit")
    public synchronized Mono<Integer> setExitCode(
            @RequestParam(value = "code", defaultValue = "0") int code
    ) {
        this.exitCode = code;
        notifyAll();
        return Mono.just(this.exitCode);
    }

    @Override
    public synchronized int getExitCode() {
        while (true) {
            if (exitCode != null) {
                return exitCode;
            }
            try {
                wait();
            } catch (InterruptedException ex) {
                // NOTHING TO DO
            }
        }
    }

}
