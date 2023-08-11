package com.pe.app.services;

import com.pe.app.model.Animal;
import com.pe.app.model.Chip;

import java.util.List;

public interface AnimalService {
    List<Animal> getAll();

    Animal getById(Long id);

    Animal save(Animal animal);

    void deleteById(Long id);
}
