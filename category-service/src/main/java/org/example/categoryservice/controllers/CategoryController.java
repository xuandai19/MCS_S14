package org.example.categoryservice.controllers;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api/v1/categories")
public class CategoryController {

    private final Map<Long, String> products = new ConcurrentHashMap<>();
    private final AtomicLong idGen = new AtomicLong(1);

    public CategoryController() {
        products.put(1L, "Product A");
        products.put(2L, "Product B");
    }

    // GET: any authenticated (has PRODUCT_READ or ROLE_USER/ADMIN)
    @GetMapping
    @PreAuthorize("hasAuthority('PRODUCT_READ') or hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<List<Map.Entry<Long, String>>> getAll() {
        return ResponseEntity.ok(new ArrayList<>(products.entrySet()));
    }

    // POST: needs PRODUCT_CREATE or ADMIN
    @PostMapping
    @PreAuthorize("hasAuthority('PRODUCT_CREATE') or hasRole('ADMIN')")
    public ResponseEntity<?> create(@RequestBody Map<String, String> body) {
        long id = idGen.getAndIncrement();
        String name = body.getOrDefault("name", "New Product");
        products.put(id, name);
        return ResponseEntity.status(HttpStatus.CREATED).body(Map.of("id", id, "name", name));
    }

    // DELETE: only ADMIN
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> delete(@PathVariable Long id) {
        if (products.remove(id) != null) {
            return ResponseEntity.ok("Deleted product " + id);
        }
        return ResponseEntity.notFound().build();
    }
}
