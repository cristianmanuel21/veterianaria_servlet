package com.pe.app.services;

import com.pe.app.model.DuenoVeterinaria;

import java.util.List;

public interface DuenoVeterinariaService {
    DuenoVeterinaria save(DuenoVeterinaria duenoVeterinaria);


    List<Long> getListById(Long id);
}
