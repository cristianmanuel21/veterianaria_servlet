package com.pe.app.services;

import com.pe.app.exception.ResourceNotFoundException;
import com.pe.app.model.Animal;
import com.pe.app.repository.AnimalRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class AnimalServiceImpl implements AnimalService{

    @Autowired
    private AnimalRepository animalRepository;

    @Override
    public List<Animal> getAll(){
        return (List<Animal>) animalRepository.findAll();
    }

    @Override
    public Animal getById(Long id){
        Optional<Animal> animal = animalRepository.findById(id);
        if (animal.isEmpty()) {
            // return new ResponseEntity<>(HttpStatus.NOT_FOUND);
            throw new ResourceNotFoundException("Animal with id " + id + " not found");
        }
        return animal.get();
    }

    @Override
    public Animal save(Animal animal){
        return animalRepository.save(animal);
    }

    @Override
    public void deleteById(Long id){
        if(this.getById(id)!=null) animalRepository.deleteById(id);
    }


}
