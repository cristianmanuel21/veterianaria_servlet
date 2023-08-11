package com.pe.app.services;

import com.pe.app.exception.ResourceNotFoundException;
import com.pe.app.model.Veterinaria;
import com.pe.app.repository.VeterinariaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class VeterinariaServiceImpl implements VeterinariaService{

    @Autowired
    private VeterinariaRepository veterinariaRepository;


    @Override
    public List<Veterinaria> getAll(){
        return (List<Veterinaria>) veterinariaRepository.findAll();
    }

    @Override
    public Veterinaria getById(Long id){
        Optional<Veterinaria> veterinaria = veterinariaRepository.findById(id);
        if (veterinaria.isEmpty()) {
            throw new ResourceNotFoundException("Veterinaria with id " + id + " not found");
        }
        return veterinaria.get();
    }

    @Override
    public Veterinaria save(Veterinaria veterinaria){
        return veterinariaRepository.save(veterinaria);
    }

    @Override
    public void deleteById(Long id){
        if(this.getById(id)!=null) veterinariaRepository.deleteById(id);
    }



}
