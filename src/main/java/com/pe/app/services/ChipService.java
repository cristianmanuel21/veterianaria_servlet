package com.pe.app.services;

import com.pe.app.model.Chip;

import java.util.List;

public interface ChipService {
    List<Chip> getAll();

    Chip getById(Long id);

    Chip save(Chip chip);

    void deleteChip(Long id);
}
