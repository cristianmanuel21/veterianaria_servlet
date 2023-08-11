package com.pe.app.services;

import com.pe.app.exception.ResourceNotFoundException;
import com.pe.app.model.Dueno;
import com.pe.app.repository.DuenoRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;


import java.util.List;
import java.util.Optional;

@Service
public class DuenoServiceImpl implements DuenoService {

    @Autowired
    private DuenoRepository duenoRepository;

    @Override
    public List<Dueno> getAll(){
        return (List<Dueno>) duenoRepository.findAll();
    }

    @Override
    public Dueno getById(Long id){
        Optional<Dueno> dueno = duenoRepository.findById(id);
        if (dueno.isEmpty()) {
            throw new ResourceNotFoundException("Dueno with id " + id + " not found");
        }
        return dueno.get();
    }

    @Override
      public Dueno save(Dueno dueno){
        return duenoRepository.save(dueno);
    }

    @Override
    public void deleteDueno(Long id){
        if(this.getById(id)!=null) duenoRepository.deleteById(id);
    }

    @Override
    public List<Dueno> getAllDuenosById(List<Long> ids){
        return duenoRepository.findAllById(ids);
    }
}
