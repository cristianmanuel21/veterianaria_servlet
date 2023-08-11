package com.pe.app.services;

import com.pe.app.model.Dueno;

import java.util.List;

public interface DuenoService {
    List<Dueno> getAll();

    Dueno getById(Long id);

    Dueno save(Dueno dueno);

    void deleteDueno(Long id);

    List<Dueno> getAllDuenosById(List<Long> ids);
}
