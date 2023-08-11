package com.pe.app.services;

import com.pe.app.model.Veterinaria;

import java.util.List;

public interface VeterinariaService {
    List<Veterinaria> getAll();

    Veterinaria getById(Long id);

    Veterinaria save(Veterinaria veterinaria);

    void deleteById(Long id);
}
