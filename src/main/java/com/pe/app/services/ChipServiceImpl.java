package com.pe.app.services;

import com.pe.app.exception.ResourceNotFoundException;
import com.pe.app.model.Chip;
import com.pe.app.repository.ChipRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import java.util.List;
import java.util.Optional;

@Service
public class ChipServiceImpl implements ChipService {

    @Autowired
    private ChipRepository chipRepository;

    @Override
    public List<Chip> getAll(){
        return (List<Chip>) chipRepository.findAll();
    }

    @Override
     public Chip getById(Long id){
        Optional<Chip> chip = chipRepository.findById(id);
        if (chip.isEmpty()) {
            // return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            throw new ResourceNotFoundException("Chip with id " + id + " not found");
        }
        return chip.get();
    }

    @Override
     public Chip save(Chip chip){
      return chipRepository.save(chip);
    }

    @Override
    public void deleteChip(Long id){
     /*   Optional<Chip> chip = chipRepository.findById(id);
        if (!chip.isPresent()) {
            throw new ResourceNotFoundException("Chip with id " + id + " not found");
        }*/
        if(this.getById(id)!=null) chipRepository.deleteById(id);
    }





}
