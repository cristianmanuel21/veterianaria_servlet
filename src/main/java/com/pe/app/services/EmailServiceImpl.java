package com.pe.app.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;


@Service
public class EmailServiceImpl implements EmailService{

    @Autowired
    private JavaMailSender emailSender;

    @Override
    public void sendSimpleMessage(String to, String subject) throws MessagingException {

        MimeMessage message = emailSender.createMimeMessage();

        MimeMessageHelper helper = new MimeMessageHelper(message, true);

       // helper.setFrom("noreply@baeldung.com");
        helper.setTo(to);
        helper.setSubject(subject);
        String content = "<b>Dear friends</b>,<br><i>Please look at this nice picture:.</i>"
                + "<br><img src='cid:imagePeluche'/>" +
                "<br><b>Peluchin, the nice pet</b>"+
                "<br><b>Best Regards</b>";
        helper.setText(content, true);

        ClassPathResource resource=new ClassPathResource("/static/images/peluche.png");
        helper.addInline("imagePeluche", resource   );

        emailSender.send(message);


    }
}
