/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.createTable('user', function(table) {
        table.increments('id').primary();
        table.string('username').notNullable().unique();
        table.string('email').notNullable().unique();
        table.string('password').notNullable();
        table.string('firstname').notNullable();
        table.string('lastname').notNullable();
        table.date('DOB').notNullable();
        table.string('profile_picture');
        table.timestamp('created_at').defaultTo(knex.fn.now());
        table.timestamp('updated_at').defaultTo(knex.fn.now());
        table.text('bio');
        table.integer('subscribers_count').defaultTo(0);
        table.integer('videos_count').defaultTo(0);
    });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
    return knex.schema.dropTable('user');
};