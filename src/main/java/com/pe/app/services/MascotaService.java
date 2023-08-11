package com.pe.app.services;

import com.pe.app.model.Mascota;

import java.util.List;

public interface MascotaService {
    List<Mascota> getAll();

    Mascota getById(Long id);

    Mascota save(Mascota mascota);

    void deleteById(Long id);
}
