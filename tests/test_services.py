import pytest
import time
from src.services.sefaz_client import CircuitBreaker

def test_circuit_breaker_state_machine():
    """Testa as transições de estado do Circuit Breaker."""
    cb = CircuitBreaker(failures_allowed=2, reset_timeout=1)
    
    # Estado Inicial
    assert cb.can_execute() is True
    assert cb.state == "CLOSED"
    
    # Primeira falha
    cb.record_failure()
    assert cb.state == "CLOSED"
    assert cb.can_execute() is True
    
    # Segunda falha (Abre o circuito)
    cb.record_failure()
    assert cb.state == "OPEN"
    assert cb.can_execute() is False
    
    # Teste de Timeout do Circuit Breaker
    time.sleep(1.1)
    
    # Após o timeout, deve permitir tentar novamente (HALF_OPEN)
    assert cb.can_execute() is True
    assert cb.state == "HALF_OPEN"
    
    # Sucesso reseta para CLOSED
    cb.record_success()
    assert cb.state == "CLOSED"
    assert cb.failures == 0
