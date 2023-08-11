package com.pe.app.controller;

import java.time.LocalDate;
import java.util.List;
import com.pe.app.services.DuenoService;
import com.pe.app.services.DuenoVeterinariaService;
import com.pe.app.services.EmailService;
import com.pe.app.services.VeterinariaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.pe.app.model.Dueno;
import com.pe.app.model.DuenoVeterinaria;
import com.pe.app.model.Veterinaria;


import javax.mail.MessagingException;


@RestController
@RequestMapping("/duenoveterinaria")
public class DuenoVeterinariaController {
	
	@Autowired
	private VeterinariaService veterinariaService;
	
	@Autowired
	private DuenoVeterinariaService duenoVeterinariaService;
	
	@Autowired
	private DuenoService duenoService;

	@Autowired
	private EmailService emailService;
	
	
	@PostMapping("/dueno/{duenoId}/veterinaria/{veterinariaId}")
	public ResponseEntity<DuenoVeterinaria> guardar(@PathVariable(name="duenoId") Long duenoId,@PathVariable(name="veterinariaId") Long veterinariaId){
		
		Dueno dueno=duenoService.getById(duenoId);
		Veterinaria veterinaria=veterinariaService.getById(veterinariaId);
		
		/*if(dueno==null && veterinaria==null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}*/
		DuenoVeterinaria duenoVeterinaria=new DuenoVeterinaria();
		duenoVeterinaria.setDueno(dueno);
		duenoVeterinaria.setVeterinaria(veterinaria);
		duenoVeterinaria.setCreated_at(LocalDate.now());
		duenoVeterinaria=duenoVeterinariaService.save(duenoVeterinaria);
		
		return new ResponseEntity<>(duenoVeterinaria,HttpStatus.CREATED);
	}
	
	
	@GetMapping("/email/veterinaria/{id}")
	public ResponseEntity<?> enviarCorreo(@PathVariable(name="id") Long id) throws MessagingException {
		Veterinaria vet=veterinariaService.getById(id);
		if(vet==null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		List<Long> duenosId= duenoVeterinariaService.getListById(vet.getId());
		if(duenosId.size()<1) {
			return new ResponseEntity<>(HttpStatus.NO_CONTENT);
		}
		
		List<Dueno> duenos = duenoService.getAllDuenosById(duenosId);
		for(Dueno dueno: duenos) {
			//emailService.sendSimpleMessage(dueno.getCorreo(),"Estimado(a) "+dueno.getNombre());
			enviarEmail(dueno);
		}
		return ResponseEntity.ok(duenos);	
	} 
	
	private String enviarEmail(Dueno dueno) {
		System.out.println("Enviado correo a: "+dueno.getCorreo());
		return "Enviado correo a: "+dueno.getCorreo();
	}
	
	
}
