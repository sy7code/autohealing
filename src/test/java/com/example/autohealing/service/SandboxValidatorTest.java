package com.example.autohealing.service;

import com.example.autohealing.exception.SandboxValidationException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class SandboxValidatorTest {

  private SandboxValidator sandboxValidator;

  @BeforeEach
  void setUp() {
    sandboxValidator = new SandboxValidator();
  }

  @Test
  @DisplayName("정상적인 스프링 코드 - 통과")
  void test_validSpringCode() {
    String validCode = """
        package com.example.autohealing.test;

        import org.springframework.stereotype.Service;
        import java.util.List;

        @Service
        public class MyService {
            public List<String> getNames() {
                return List.of("A", "B");
            }
        }
        """;

    assertDoesNotThrow(() -> sandboxValidator.validate(validCode));
  }

  @Test
  @DisplayName("화이트리스트에 없는 패키지 임포트 - 차단")
  void test_invalidImport_blocked() {
    String invalidCode = """
        package com.example.autohealing.test;

        import java.net.Socket;
        import org.springframework.stereotype.Service;

        @Service
        public class MyService {
            public void connect() {
                // ...
            }
        }
        """;

    SandboxValidationException ex = assertThrows(SandboxValidationException.class,
        () -> sandboxValidator.validate(invalidCode));

    assertTrue(ex.getMessage().contains("화이트리스트에 없는 외부 패키지 임포트"));
    assertTrue(ex.getMessage().contains("java.net.Socket"));
  }

  @Test
  @DisplayName("블랙리스트 패키지 명시적 임포트 - 차단")
  void test_restrictedImport_blocked() {
    String invalidCode = """
        import java.lang.reflect.Method;

        public class Hack {
        }
        """;

    SandboxValidationException ex = assertThrows(SandboxValidationException.class,
        () -> sandboxValidator.validate(invalidCode));

    assertTrue(ex.getMessage().contains("허용되지 않은 악성 클래스/패키지"));
    assertTrue(ex.getMessage().contains("java.lang.reflect.Method"));
  }

  @Test
  @DisplayName("악의적인 시스템 메서드 호출 (System.exit) - 차단")
  void test_maliciousMethodCall_systemExit_blocked() {
    String maliciousCode = """
        package com.example.autohealing.test;
        import java.util.List;

        public class MyService {
            public void doSomething() {
                System.exit(1);
            }
        }
        """;

    SandboxValidationException ex = assertThrows(SandboxValidationException.class,
        () -> sandboxValidator.validate(maliciousCode));

    assertTrue(ex.getMessage().contains("치명적이거나 악용될 수 있는 메서드 호출"));
    assertTrue(ex.getMessage().contains("exit"));
  }

  @Test
  @DisplayName("악의적인 시스템 메서드 호출 (Runtime.exec) - 차단")
  void test_maliciousMethodCall_runtimeExec_blocked() {
    String maliciousCode = """
        public class Hack {
            public void hack() throws Exception {
                Runtime.getRuntime().exec("rm -rf /");
            }
        }
        """;

    SandboxValidationException ex = assertThrows(SandboxValidationException.class,
        () -> sandboxValidator.validate(maliciousCode));

    assertTrue(ex.getMessage().contains("치명적이거나 악용될 수 있는 메서드 호출 감지 (exec)"));
  }

  @Test
  @DisplayName("권장되지 않는 XML 파서(Spring) 임포트 - 차단 (RCE 방어)")
  void test_springXmlRce_blocked() {
    String code = """
        import org.springframework.context.support.ClassPathXmlApplicationContext;

        public class BadSpring {
        }
        """;

    SandboxValidationException ex = assertThrows(SandboxValidationException.class,
        () -> sandboxValidator.validate(code));
    assertTrue(ex.getMessage().contains("악성 클래스/패키지가 임포트"));
  }
}
