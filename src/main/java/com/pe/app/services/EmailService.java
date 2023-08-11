package com.pe.app.services;

import javax.mail.MessagingException;

public interface EmailService {
    public void sendSimpleMessage(String to, String subject) throws MessagingException;
}
