package com.example.ledger;

import jakarta.persistence.EntityManager;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
class InvoiceController {
    private final EntityManager entities;
    private final InvoiceRepository invoices;

    InvoiceController(EntityManager entities, InvoiceRepository invoices) {
        this.entities = entities;
        this.invoices = invoices;
    }

    @PutMapping("/invoices/{ref}")
    Invoice replace(@PathVariable Long ref, @RequestBody Invoice body) {
        body.ref = ref;
        // ruleid: traust-java-mass-assignment-request-body-entity
        return entities.merge(body);
    }

    @PostMapping("/invoices")
    Invoice open(@Valid @RequestBody Invoice body) {
        // ruleid: traust-java-mass-assignment-request-body-entity
        return invoices.save(body);
    }

    @PatchMapping("/invoices/{ref}")
    Invoice rename(@PathVariable Long ref, @RequestBody RenameRequest body) {
        Invoice found = invoices.findById(ref).orElseThrow();
        found.label = body.label;
        // ok: traust-java-mass-assignment-request-body-entity
        return invoices.save(found);
    }

    @PostMapping("/drafts")
    Invoice draft(@RequestBody InvoiceDto body) {
        // ok: traust-java-mass-assignment-request-body-entity
        return invoices.save(body.toEntity());
    }
}
