package src.main.java.com.bankapp.model;

//describes whether a customer is allowed to log in or not
//If they have surpased the amount of log in attempts, they are LOCKED from the account
//This is a value stored in the 'users' table in the database
public enum UserStatus {ACTIVE, LOCKED}

