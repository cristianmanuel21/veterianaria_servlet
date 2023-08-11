package com.pe.app.services;

import com.pe.app.model.DuenoVeterinaria;
import com.pe.app.repository.DuenoVeterinariaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class DuenoVeterinariaServiceImpl implements DuenoVeterinariaService{

    @Autowired
    private DuenoVeterinariaRepository duenoVeterinariaRepository;

    @Override
    public DuenoVeterinaria save(DuenoVeterinaria duenoVeterinaria) {
        return duenoVeterinariaRepository.save(duenoVeterinaria);
    }

    @Override
    public List<Long> getListById(Long id){
        return duenoVeterinariaRepository.findDuenosBytVetId(id);
    }


}
