package com.pe.app.services;

import com.pe.app.exception.ResourceNotFoundException;
import com.pe.app.model.Mascota;
import com.pe.app.repository.MascotaRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class MascotaServiceImpl implements MascotaService{

    @Autowired
    private MascotaRepository mascotaRepository;

    @Override
    public List<Mascota> getAll(){
        return (List<Mascota>) mascotaRepository.findAll();
    }

    @Override
    public Mascota getById(Long id){
        Optional<Mascota> mascota = mascotaRepository.findById(id);
        if (mascota.isEmpty()) {
            throw new ResourceNotFoundException("Mascota with id " + id + " not found");
        }
        return mascota.get();
    }

    @Override
    public Mascota save(Mascota mascota) {
        return mascotaRepository.save(mascota);
    }

    @Override
    public void deleteById(Long id) {
        if(this.getById(id)!=null) mascotaRepository.deleteById(id);
    }



}
