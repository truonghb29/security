package com.example.security.entity;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class Todo {

    private String id;

    @NotBlank(message = "Title is required")
    @Size(max = 100, message = "Title cannot exceed 100 characters")
    private String title;

    private boolean completed ;

    public Todo() {}

    public Todo( String title) {
        this.title = title;
        this.completed = false;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public boolean isCompleted() {
        return completed;
    }

    public void setCompleted(boolean completed) {
        this.completed = completed;
    }
}
