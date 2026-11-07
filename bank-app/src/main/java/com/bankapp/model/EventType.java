package src.main.java.com.bankapp.model;

//every kind of security event that can be logged, supporting CWE-778
//is it basically a checklist of what do we log after an action occurs
public enum EventType
{
    REGISTER_SUCESS, REGISTER_FAILURE,
    LOGIN_SUCCESS, LOGIN_FAILURE,
    ACCONT_LOCKED, ACCOUNT_UNLOCKED,
    LOGOUT, SESSION_TIMEOUT,
    BALANCE_VIEWED,
    DEPOSIT_SUCCESS, DEPOSIT_FAILURE,
    WITHDRAWAL_REQUESTED, WITHDRAWAL_CONFIRMED,
    WITHDRAWAL_CANCELLED, WITHDRAWAL_DENIED,
    REAUTH_FAILURE,
    UNAUTHORIZED_ATTEMPT, WORKFLOW_VIOLATION
}