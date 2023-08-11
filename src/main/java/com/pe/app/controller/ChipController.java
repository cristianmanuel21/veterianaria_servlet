package com.pe.app.controller;

import java.net.URI;
import javax.validation.Valid;
import com.pe.app.services.ChipService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import com.pe.app.model.Chip;


@RestController
@RequestMapping("/chip")
public class ChipController {

	@Autowired
	private ChipService chipService;

	@GetMapping("/{id}")
	public ResponseEntity<Chip> getChip(@PathVariable(name = "id") Long id) {
		Chip chip = chipService.getById(id);
		return new ResponseEntity<>(chip, HttpStatus.OK);
	}

	@GetMapping
	public ResponseEntity<?> getAll(){
		return new ResponseEntity<>(chipService.getAll(),HttpStatus.OK);
	}

	@PutMapping("/{id}")
	public ResponseEntity<Chip> updateChip(@RequestBody Chip chip,@PathVariable(name="id") Long id){
		Chip newChip = chipService.getById(id);
		if(chip.getMarca()!=null && !chip.getMarca().isEmpty()) newChip.setMarca(chip.getMarca());
		if(chip.getDescripcion()!=null && !chip.getDescripcion().isEmpty()) newChip.setDescripcion(chip.getDescripcion());
		return new ResponseEntity<>(chipService.save(newChip), HttpStatus.CREATED);
	}


	@PostMapping
	public ResponseEntity<Chip> saveChip(@Valid @RequestBody Chip chip) {
		Chip newChip = chipService.save(chip);
		HttpHeaders responseHeaders = new HttpHeaders();
		URI newCacheUri = ServletUriComponentsBuilder.fromCurrentRequest().path("/{id}").buildAndExpand(newChip.getId())
				.toUri();
		responseHeaders.setLocation(newCacheUri);
		return new ResponseEntity<>(newChip, responseHeaders, HttpStatus.CREATED);
		// return new ResponseEntity<>(null,HttpStatus.CREATED);
	}

	 @DeleteMapping("/{id}")
	public ResponseEntity<Void> deleteChip(Long id){
		chipService.deleteChip(id);
		return new ResponseEntity<>(HttpStatus.NO_CONTENT);
	 }

}
