package com.pe.app.controller;

import java.net.URI;
import com.pe.app.services.AnimalService;
import com.pe.app.services.ChipService;
import com.pe.app.services.DuenoService;
import com.pe.app.services.MascotaService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.pe.app.model.Animal;
import com.pe.app.model.Chip;
import com.pe.app.model.Dueno;
import com.pe.app.model.Mascota;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.validation.Valid;

@RestController
@RequestMapping("/mascota")
public class MascotaController {

	@Autowired
	private MascotaService mascotaService;

	@Autowired
	private DuenoService duenoService;

	@Autowired
	private ChipService chipService;

	@Autowired
	private AnimalService animalService;

	@GetMapping
	public ResponseEntity<?> getAll(){
		return new ResponseEntity<>(mascotaService.getAll(),HttpStatus.OK);
	}

	@GetMapping("/{id}")
	public ResponseEntity<Mascota> getMascota(@PathVariable(name="id") Long id){
		Mascota mascota = mascotaService.getById(id);
		return new ResponseEntity<>(mascota,HttpStatus.OK);
	}

	@PostMapping("/animal/{animalId}/chip/{chipId}/dueno/{duenoId}")
	public ResponseEntity<Mascota> saveMascota(@Valid @RequestBody Mascota mascota, @PathVariable("animalId") Long animalId,
											   @PathVariable("chipId") Long chipId, @PathVariable("duenoId") Long duenoId){
		Animal animalOp=animalService.getById(animalId);
		Chip chipOp=chipService.getById(chipId);
		Dueno duenoOp=duenoService.getById(duenoId);
		if(animalOp==null && chipOp==null && duenoOp==null) {
			return new ResponseEntity<>(HttpStatus.NOT_FOUND);
		}
		Mascota newMascota;
		mascota.setAnimal(animalOp);
		mascota.setChip(chipOp);
		mascota.setDueno(duenoOp);
		newMascota=mascotaService.save(mascota);
		HttpHeaders responseHeaders = new HttpHeaders();
		URI newCacheUri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(newMascota.getId())
				.toUri();
		responseHeaders.setLocation(newCacheUri);
		return new ResponseEntity<>(newMascota,responseHeaders,HttpStatus.CREATED);
	}

	@PutMapping("/{id}")
	public ResponseEntity<Mascota> updateMascota(@RequestBody Mascota mascota, @PathVariable(name="id") Long id){
		Mascota newMascota = mascotaService.getById(id);
		if(mascota.getNombre()!=null && !mascota.getNombre().isEmpty()) newMascota.setNombre(mascota.getNombre());
		return new ResponseEntity<>(mascotaService.save(newMascota), HttpStatus.CREATED);
	}

}
